// src/services/otpService.js
const crypto   = require('crypto');
const { totp, authenticator } = require('otplib');
const QRCode   = require('qrcode');
const { generateNumericOTP, hashToken } = require('../utils/security');
const emailNotifier = require('./emailNotifier');
const emailPayloads = require('../email/emailPayloads');
const env           = require('../config/env');

const OTP_EXPIRY_MS = env.OTP_EXPIRY_MS;
const OTP_LENGTH    = env.OTP_LENGTH;
const TOTP_ISSUER   = env.TOTP_ISSUER;
const MAX_OTP_ATTEMPTS = 5;

class OTPService {
  /**
   * Determine the best available OTP method for a user.
   * Priority: totp > email > sms (if preferred or configured).
   */
  getBestMethod(user) {
    if (user.twoFactorAuth?.enabled && user.twoFactorAuth?.secret) return 'totp';
    if (user.otpSettings?.preferredMethod === 'sms' && user.phoneNumber && user.phoneVerified) return 'sms';
    return 'email';
  }

  isEnabled(settings = {}) {
    return settings.enabled ?? !!env.OTP_METHOD;
  }

  /**
   * Generate and send an OTP to the user via the preferred delivery method.
   * @param {Object} user     - Mongoose user document
   * @param {string} purpose  - 'login' | 'reset' | 'verification' | 'sensitive_op'
   * @param {string} method   - forced method override (optional)
   * @returns {Object} { method, maskedDestination }
   */
  async generateAndSend(user, purpose = 'login', method = null) {
    const deliveryMethod = method || this.getBestMethod(user);

    if (deliveryMethod === 'totp') {
      // TOTP is verified client-side — no code to send
      return { method: 'totp', maskedDestination: 'authenticator app' };
    }

    // Generate OTP code
    const code    = generateNumericOTP(OTP_LENGTH);
    const hashed  = hashToken(code);
    const expires = new Date(Date.now() + OTP_EXPIRY_MS);

    // Store on user document
    user.currentOTP = {
      code:        null,       // never store plaintext
      hashedCode:  hashed,
      type:        deliveryMethod,
      purpose,
      expiresAt:   expires,
      attempts:    0,
      maxAttempts: MAX_OTP_ATTEMPTS,
      lastSent:    new Date(),
      verified:    false,
    };
    await user.save();

    // Deliver
    if (deliveryMethod === 'email') {
      emailNotifier.send(emailPayloads.otpEmail(user, code));
      return { method: 'email', maskedDestination: this._maskEmail(user.email) };
    }

    if (deliveryMethod === 'sms') {
      // SMS delivery – extend if you have an SMS provider
      return { method: 'sms', maskedDestination: this._maskPhone(user.phoneNumber) };
    }

    throw new Error(`Unsupported OTP delivery method: ${deliveryMethod}`);
  }

  /**
   * Verify an OTP code.
   * @returns {{ valid: boolean, reason?: string }}
   */
  async verifyOTP(user, code, purpose = null) {
    const otp = user.currentOTP;
    if (!otp || !otp.hashedCode) return { valid: false, reason: 'NO_OTP_PENDING' };

    if (purpose && otp.purpose !== purpose) return { valid: false, reason: 'PURPOSE_MISMATCH' };
    if (otp.verified)                       return { valid: false, reason: 'ALREADY_USED' };
    if (new Date() > otp.expiresAt)         return { valid: false, reason: 'OTP_EXPIRED' };
    if (otp.attempts >= otp.maxAttempts)    return { valid: false, reason: 'MAX_ATTEMPTS_EXCEEDED' };

    otp.attempts += 1;

    const inputHash  = hashToken(code);
    const valid      = crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(otp.hashedCode));

    if (valid) {
      otp.verified     = true;
      otp.hashedCode   = null;
      await user.save();
      return { valid: true };
    }

    await user.save();
    return { valid: false, reason: 'INVALID_CODE' };
  }

  // ─── TOTP Setup ────────────────────────────────────────────────────────────

  async setupTOTP(user) {
    const secret   = authenticator.generateSecret();
    const otpauth  = authenticator.keyuri(user.email, TOTP_ISSUER, secret);
    const qrCode   = await QRCode.toDataURL(otpauth);

    user.twoFactorAuth.secret         = secret;
    user.twoFactorAuth.enabled        = false;
    user.twoFactorAuth.setupCompleted = false;
    await user.save();

    return { secret, qrCode, manualEntryKey: secret, setupUri: otpauth };
  }

  async verifyTOTPSetup(user, token) {
    const secret = user.twoFactorAuth?.secret;
    if (!secret) throw new Error('TOTP not initialized');
    const valid = authenticator.verify({ token, secret });
    if (!valid) return false;

    user.twoFactorAuth.enabled        = true;
    user.twoFactorAuth.setupCompleted = true;
    user.twoFactorAuth.lastUsed       = new Date();

    // Generate backup codes
    user.twoFactorAuth.backupCodes = this._generateBackupCodes(10);
    await user.save();
    return true;
  }

  verifyTOTP(user, token) {
    const secret = user.twoFactorAuth?.secret;
    if (!secret || !user.twoFactorAuth.enabled) return false;
    return authenticator.verify({ token, secret });
  }

  async useBackupCode(user, code) {
    const bc = user.twoFactorAuth?.backupCodes?.find(
      (b) => !b.used && b.code === code.toUpperCase()
    );
    if (!bc) return false;
    bc.used   = true;
    bc.usedAt = new Date();
    await user.save();
    return true;
  }

  _generateBackupCodes(count = 10) {
    return Array.from({ length: count }, () => ({
      code:    crypto.randomBytes(4).toString('hex').toUpperCase(),
      used:    false,
      usedAt:  null,
      createdAt: new Date(),
    }));
  }

  _maskEmail(email) {
    if (!email) return '';
    const [local, domain] = email.split('@');
    return `${local[0]}***@${domain}`;
  }

  _maskPhone(phone) {
    if (!phone) return '';
    return phone.slice(0, 3) + '***' + phone.slice(-2);
  }

  getAvailableMethods(user) {
    const methods = [];
    if (user.twoFactorAuth?.enabled && user.twoFactorAuth?.secret)
      methods.push({ type: 'totp', name: 'Authenticator App' });
    if (user.email && user.emailVerified)
      methods.push({ type: 'email', name: 'Email', destination: this._maskEmail(user.email) });
    if (user.phoneNumber && user.phoneVerified)
      methods.push({ type: 'sms', name: 'SMS', destination: this._maskPhone(user.phoneNumber) });
    return methods;
  }
}

module.exports = new OTPService();
