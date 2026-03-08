// src/utils/helper.js
const jwt = require('jsonwebtoken');

/**
 * Decode a JWT without verifying (useful for reading claims from expired tokens).
 */
const decodeToken = (token) => {
  try {
    return jwt.decode(token);
  } catch {
    return null;
  }
};

/**
 * Build a paginated/sorted mongoose query object from request query params.
 */
const buildPaginationOptions = (query) => {
  const page  = Math.max(1, parseInt(query.page  || '1',  10));
  const limit = Math.min(100, Math.max(1, parseInt(query.limit || '20', 10)));
  const skip  = (page - 1) * limit;

  const sortField = query.sortBy || 'createdAt';
  const sortOrder = query.order === 'asc' ? 1 : -1;
  const sort = { [sortField]: sortOrder };

  return { page, limit, skip, sort };
};

/**
 * Safe JSON parse – returns null on failure instead of throwing.
 */
const safeJsonParse = (str, fallback = null) => {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
};

/**
 * Mask an email for display (e.g. j***@example.com)
 */
const maskEmail = (email) => {
  if (!email) return '';
  const [local, domain] = email.split('@');
  return `${local[0]}***@${domain}`;
};

/**
 * Mask a phone number for display.
 */
const maskPhone = (phone) => {
  if (!phone) return '';
  return phone.slice(0, 3) + '***' + phone.slice(-2);
};

/**
 * Strip sensitive fields from a user object before returning it to clients.
 * Also reduces a populated `role` object to just its name string.
 * The `_id` → `id` renaming is handled centrally by serialize() in responseHelper.
 *
 * Removed fields:
 *  - hash_password              — bcrypt hash
 *  - emailVerificationToken     — raw/hashed token
 *  - emailVerificationTokenExpiry
 *  - passwordReset              — hashed reset token + metadata
 *  - unlockToken                — hashed unlock token
 *  - loginSecurity              — internal lockout counters
 *  - refreshTokens              — hashed JTIs
 *  - currentOTP                 — live OTP code/hash
 *  - twoFactorAuth              — TOTP secret + backup codes
 *  - activeSessions             — session IPs / user-agents (internal)
 *  - loginHistory               — IP / device history (internal)
 *  - securityEvents             — internal security audit log
 *  - knownDevices               — device fingerprints / IPs
 *  - __v                        — Mongoose version key
 */
const sanitizeUser = (user) => {
  const obj = user.toObject ? user.toObject() : { ...user };

  // Normalize role — reduce populated role object to just the name string
  if (obj.role && typeof obj.role === 'object' && obj.role.name !== undefined) {
    obj.role = obj.role.name;
  }

  // Credentials & tokens
  delete obj.hash_password;
  delete obj.emailVerificationToken;
  delete obj.emailVerificationTokenExpiry;
  delete obj.passwordReset;
  delete obj.unlockToken;

  // Internal security state
  delete obj.loginSecurity;
  delete obj.refreshTokens;
  delete obj.currentOTP;
  delete obj.twoFactorAuth;

  // Internal history / session tracking
  delete obj.activeSessions;
  delete obj.loginHistory;
  delete obj.securityEvents;
  delete obj.knownDevices;

  delete obj.__v;
  // Soft-delete tombstone + actor audit — never expose from auth responses
  delete obj.isDeleted;
  delete obj.deletedAt;
  delete obj.createdBy;
  delete obj.updatedBy;
  delete obj.deletedBy;
  // _id → id renaming is handled by serialize() in responseHelper
  return obj;
};

/**
 * Convert a Mongoose subdocument to a plain object.
 * _id → id renaming is handled by serialize() in responseHelper.
 */
const stripId = (doc) => (doc.toObject ? doc.toObject() : { ...doc });

module.exports = { decodeToken, buildPaginationOptions, safeJsonParse, maskEmail, maskPhone, sanitizeUser, stripId };
