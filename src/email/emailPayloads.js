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
exports.welcome = (user, verifyLink) => ({
  to: user.email, templateKey: 'USER_CREATED',
  variables: { name: name(user), verifyLink },
});
exports.emailVerificationLink = (user, verifyLink) => ({
  to: user.email, templateKey: 'emailVerificationTemplate',
  variables: { name: name(user), verifyLink, expiryHours: env.EMAIL_VERIFY_EXPIRY_HOURS },
});
exports.emailVerified = (user) => ({
  to: user.email, templateKey: 'EMAIL_VERIFIED',
  variables: { name: name(user) },
});

// ─── Password ──────────────────────────────────────────────────────────────────
exports.passwordResetRequested = (user, resetLink) => ({
  to: user.email, templateKey: 'PASSWORD_RESET_REQUESTED',
  variables: { name: name(user), resetLink, expiryHours: RESET_EXPIRY },
});
exports.passwordResetCompleted = (user) => ({
  to: user.email, templateKey: 'PASSWORD_RESET_COMPLETED',
  variables: { name: name(user) },
});
exports.passwordChanged = (user) => ({
  to: user.email, templateKey: 'PASSWORD_CHANGED',
  variables: { name: name(user) },
});

// ─── Login Security ────────────────────────────────────────────────────────────
exports.loginFailed = (user, ip) => ({
  to: user.email, templateKey: 'LOGIN_FAILED',
  variables: { name: name(user), ip, time: now() },
});
exports.accountLocked = (user) => ({
  to: user.email, templateKey: 'ACCOUNT_LOCKED',
  variables: { name: name(user), maxAttempts: MAX_ATTEMPTS },
});
exports.newDeviceLogin = (user, deviceInfo) => ({
  to: user.email, templateKey: 'NEW_DEVICE_LOGIN',
  variables: { name: name(user), device: deviceInfo.device, location: deviceInfo.location, ip: deviceInfo.ip, time: now() },
});

// ─── Account Unlock ────────────────────────────────────────────────────────────
exports.accountUnlockRequest = (user, unlockLink) => ({
  to: user.email, templateKey: 'ACCOUNT_RECOVERY_REQUESTED',
  variables: { name: name(user), unlockLink, expiryHours: 1 },
});
exports.accountUnlockConfirmed = (user) => ({
  to: user.email, templateKey: 'ACCOUNT_UNLOCKED',
  variables: { name: name(user) },
});

// ─── Session ───────────────────────────────────────────────────────────────────
exports.logoutAllDevices = (user) => ({
  to: user.email, templateKey: 'logoutAllDevicesTemplate',
  variables: { name: name(user), time: now() },
});

// ─── OTP / MFA ─────────────────────────────────────────────────────────────────
exports.otpEmail = (user, otp, purpose = 'verification') => ({
  to: user.email, templateKey: 'otpEmailTemplate',
  variables: { name: name(user), otp, purpose, expiryMinutes: OTP_EXPIRY },
});
exports.twoFactorSetup = (user, qrCodeUrl, secret) => ({
  to: user.email, templateKey: 'twoFactorSetupTemplate',
  variables: { name: name(user), qrCodeUrl, secret },
});
exports.backupCodes = (user, codes = []) => ({
  to: user.email, templateKey: 'backupCodesTemplate',
  variables: { name: name(user), codes },
});
exports.mfaEnabled = (user) => ({
  to: user.email, templateKey: 'MFA_ENABLED',
  variables: { name: name(user), time: now() },
});
exports.mfaDisabled = (user) => ({
  to: user.email, templateKey: 'MFA_DISABLED',
  variables: { name: name(user), time: now() },
});

// ─── Social Login ──────────────────────────────────────────────────────────────
exports.socialLoginConnected = (user, provider) => ({
  to: user.email, templateKey: 'SOCIAL_LOGIN_CONNECTED',
  variables: { name: name(user), provider, time: now() },
});
exports.socialLoginDisconnected = (user, provider) => ({
  to: user.email, templateKey: 'SOCIAL_LOGIN_DISCONNECTED',
  variables: { name: name(user), provider, time: now() },
});

// ─── Account Lifecycle ─────────────────────────────────────────────────────────
exports.accountDeleted = (user) => ({
  to: user.email, templateKey: 'ACCOUNT_TERMINATED',
  variables: { name: name(user) },
});
