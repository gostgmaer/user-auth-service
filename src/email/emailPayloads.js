// src/email/emailPayloads.js
// Payload builders for every email sent by the auth microservice.
// Each builder returns the exact JSON body expected by POST /send-email.
'use strict';

const env = require('../config/env');

const MAX_ATTEMPTS = env.MAX_LOGIN_ATTEMPTS;
const RESET_EXPIRY = env.PASSWORD_RESET_EXPIRY_HOURS;
const OTP_EXPIRY   = env.OTP_EXPIRY_MINUTES;

// ─── Helper ────────────────────────────────────────────────────────────────────
const name = (user) => user.firstName || user.username;
const now  = () => new Date().toISOString();

// ─── Registration & Email Verification ────────────────────────────────────────
// Sent to the newly registered user — welcome + verify email CTA
exports.welcome = (user, verifyLink) => ({
  to: user.email, templateId: 'USER_WELCOME',
  data: {
    userId:    user._id?.toString(),
    username:  user.username,
    email:     user.email,
    verifyLink,
    timestamp: new Date().toISOString(),
  },
});
// Sent to admin when a new user registers
exports.adminUserRegistered = (user, req) => ({
  to: env.ADMIN_EMAIL,
  templateId: 'ADMIN_USER_REGISTERED',
  data: {
    userId:       user._id?.toString(),
    username:     user.username,
    email:        user.email,
    registeredAt: new Date().toISOString(),
    ipAddress:    req?.ip || req?.socket?.remoteAddress || 'Unknown',
  },
});
exports.emailVerificationLink = (user, verifyLink) => ({
  to: user.email, templateId: 'emailVerificationTemplate',
  data: { name: name(user), verifyLink, expiryHours: env.EMAIL_VERIFY_EXPIRY_HOURS },
});
exports.emailVerified = (user) => ({
  to: user.email, templateId: 'EMAIL_VERIFIED',
  data: { name: name(user) },
});

// ─── Password ──────────────────────────────────────────────────────────────────
exports.passwordResetRequested = (user, resetLink) => ({
  to: user.email, templateId: 'PASSWORD_RESET_REQUESTED',
  data: { name: name(user), resetLink, expiryHours: RESET_EXPIRY },
});
exports.passwordResetCompleted = (user) => ({
  to: user.email, templateId: 'PASSWORD_RESET_COMPLETED',
  data: { name: name(user) },
});
exports.passwordChanged = (user) => ({
  to: user.email, templateId: 'PASSWORD_CHANGED',
  data: { name: name(user) },
});

// ─── Login Security ────────────────────────────────────────────────────────────
exports.loginFailed = (user, ip) => ({
  to: user.email, templateId: 'LOGIN_FAILED',
  data: { name: name(user), ip, time: now() },
});
exports.accountLocked = (user) => ({
  to: user.email, templateId: 'ACCOUNT_LOCKED',
  data: { name: name(user), maxAttempts: MAX_ATTEMPTS },
});
exports.newDeviceLogin = (user, deviceInfo) => ({
  to: user.email, templateId: 'NEW_DEVICE_LOGIN',
  data: { name: name(user), device: deviceInfo.device, location: deviceInfo.location, ip: deviceInfo.ip, time: now() },
});

// ─── Account Unlock ────────────────────────────────────────────────────────────
exports.accountUnlockRequest = (user, unlockLink) => ({
  to: user.email, templateId: 'ACCOUNT_RECOVERY_REQUESTED',
  data: { name: name(user), unlockLink, expiryHours: 1 },
});
exports.accountUnlockConfirmed = (user) => ({
  to: user.email, templateId: 'ACCOUNT_UNLOCKED',
  data: { name: name(user) },
});

// ─── Session ───────────────────────────────────────────────────────────────────
exports.logoutAllDevices = (user) => ({
  to: user.email, templateId: 'logoutAllDevicesTemplate',
  data: { name: name(user), time: now() },
});

// ─── OTP / MFA ─────────────────────────────────────────────────────────────────
exports.otpEmail = (user, otp, purpose = 'verification') => ({
  to: user.email, templateId: 'otpEmailTemplate',
  data: { name: name(user), otp, purpose, expiryMinutes: OTP_EXPIRY },
});
exports.twoFactorSetup = (user, qrCodeUrl, secret) => ({
  to: user.email, templateId: 'twoFactorSetupTemplate',
  data: { name: name(user), qrCodeUrl, secret },
});
exports.backupCodes = (user, codes = []) => ({
  to: user.email, templateId: 'backupCodesTemplate',
  data: { name: name(user), codes },
});
exports.mfaEnabled = (user) => ({
  to: user.email, templateId: 'MFA_ENABLED',
  data: { name: name(user), time: now() },
});
exports.mfaDisabled = (user) => ({
  to: user.email, templateId: 'MFA_DISABLED',
  data: { name: name(user), time: now() },
});

// ─── Social Login ──────────────────────────────────────────────────────────────
exports.socialLoginConnected = (user, provider) => ({
  to: user.email, templateId: 'SOCIAL_LOGIN_CONNECTED',
  data: { name: name(user), provider, time: now() },
});
exports.socialLoginDisconnected = (user, provider) => ({
  to: user.email, templateId: 'SOCIAL_LOGIN_DISCONNECTED',
  data: { name: name(user), provider, time: now() },
});

// ─── Account Lifecycle ─────────────────────────────────────────────────────────
exports.accountDeleted = (user) => ({
  to: user.email, templateId: 'ACCOUNT_TERMINATED',
  data: { name: name(user) },
});

// ─── Profile Security Changes ─────────────────────────────────────────────────
// Sent when the user's own profile update changes a security-sensitive field
exports.phoneChanged = (user) => ({
  to: user.email, templateId: 'PHONE_CHANGED',
  data: { name: name(user), newPhone: user.phoneNumber, time: now() },
});
exports.usernameChanged = (user, oldUsername) => ({
  to: user.email, templateId: 'USERNAME_CHANGED',
  data: { name: name(user), oldUsername, newUsername: user.username, time: now() },
});
