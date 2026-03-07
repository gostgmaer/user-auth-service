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
 */
const sanitizeUser = (user) => {
  const obj = user.toObject ? user.toObject() : { ...user };
  delete obj.hash_password;
  delete obj.passwordReset;
  delete obj.emailVerificationTokens;
  delete obj.refreshTokens;
  delete obj.authTokens;
  delete obj.twoFactorAuth;
  delete obj.currentOTP;
  delete obj.securityEvents;
  delete obj.__v;
  return obj;
};

module.exports = { decodeToken, buildPaginationOptions, safeJsonParse, maskEmail, maskPhone, sanitizeUser };
