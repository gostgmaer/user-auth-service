// src/utils/security.js
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const env = require('../config/env');

const BCRYPT_ROUNDS = env.BCRYPT_ROUNDS;

/** Generate a cryptographically secure random token (default: 32 bytes → 64 hex chars). */
const generateSecureToken = (byteLength = 32) =>
  crypto.randomBytes(byteLength).toString('hex');

/** Generate a numeric OTP string of specified length. */
const generateNumericOTP = (digits = 6) => {
  const buffer = crypto.randomBytes(4);
  const num = buffer.readUInt32BE(0);
  return (num % Math.pow(10, digits)).toString().padStart(digits, '0');
};

/** Hash a plain-text value with bcrypt. */
const hashPassword = (plain) => bcrypt.hash(plain, BCRYPT_ROUNDS);

/** Compare a plain-text value against a bcrypt hash. */
const verifyPassword = (plain, hash) => bcrypt.compare(plain, hash);

/** Hash sensitive token data with SHA-256 (deterministic, for storage + lookup). */
const hashToken = (token) =>
  crypto.createHash('sha256').update(token).digest('hex');

/**
 * Timing-safe comparison of two strings to prevent timing attacks.
 * Both must be the same length (padding is applied if not).
 */
const timingSafeEqual = (a, b) => {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    // Compare with a dummy buffer to consume constant time, then return false
    crypto.timingSafeEqual(bufA, Buffer.alloc(bufA.length));
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
};

/**
 * Validate password strength: ≥ 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char.
 */
const checkPasswordStrength = (password) => {
  const checks = {
    minLength:     password.length >= 8,
    hasUppercase:  /[A-Z]/.test(password),
    hasLowercase:  /[a-z]/.test(password),
    hasNumbers:    /\d/.test(password),
    hasSpecialChars: /[@$!%*?&^#()_\-+=~`|\\[\]{};:'",<.>/?]/.test(password),
  };
  const feedback = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => {
      const msgs = {
        minLength:      'Must be at least 8 characters',
        hasUppercase:   'Must contain at least one uppercase letter',
        hasLowercase:   'Must contain at least one lowercase letter',
        hasNumbers:     'Must contain at least one digit',
        hasSpecialChars:'Must contain at least one special character',
      };
      return msgs[k];
    });
  return { isValid: feedback.length === 0, checks, feedback };
};

module.exports = {
  generateSecureToken, generateNumericOTP,
  hashPassword, verifyPassword, hashToken,
  timingSafeEqual, checkPasswordStrength,
};
