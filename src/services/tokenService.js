// src/services/tokenService.js
'use strict';

const jwt  = require('jsonwebtoken');
const fs   = require('fs');
const { v4: uuidv4 } = require('uuid');
const jwtConfig = require('../config/jwt');
const { hashToken } = require('../utils/security');
const env       = require('../config/env');

// ─── Asymmetric key loading ───────────────────────────────────────────────────
// When JWT_ALGORITHM is RS*/ES*, load PEM keys from the paths specified in env.
// Falls back to symmetric HMAC secrets for HS* algorithms.
const _isAsymmetric = /^(RS|ES|PS)\d+$/.test(jwtConfig.algorithm);

const _loadKey = (pathEnv, fallback) => {
  if (!_isAsymmetric) return fallback;
  if (!pathEnv) return fallback;
  try {
    return fs.readFileSync(pathEnv);
  } catch (err) {
    const logger = require('../utils/logger');
    logger.warn(`JWT key file not found at ${pathEnv}, falling back to secret`, { error: err.message });
    return fallback;
  }
};

// Only load from disk once at module initialisation — not per-request
const signingKey   = _loadKey(jwtConfig.privateKeyPath, jwtConfig.accessSecret);
const verifyingKey = _loadKey(jwtConfig.publicKeyPath,  jwtConfig.accessSecret);

/**
 * Build JWT sign options with standard claims.
 */
const buildOptions = (_secret, expiry) => ({
  algorithm: jwtConfig.algorithm,
  expiresIn: expiry,
  issuer:    jwtConfig.issuer,
  audience:  jwtConfig.audience,
});

/**
 * Build JWT verify options (uses public key for asymmetric, shared secret for HMAC).
 */
const buildVerifyOptions = () => ({
  algorithms: [jwtConfig.algorithm],
  issuer:     jwtConfig.issuer,
  audience:   jwtConfig.audience,
});

/**
 * Issue access token, refresh token, and ID token for a user + session.
 * Every token carries a unique jti (UUID v4) for granular revocation.
 */
const generateTokens = (user, sessionId) => {
  const accessJti  = uuidv4();
  const refreshJti = uuidv4();
  const idJti      = uuidv4();

  const baseClaims = {
    sub:      user._id.toString(),
    tenantId: user.tenantId,
    email:    user.email,
    role:     user.role?.name || null,
    sessionId,
  };

  // For asymmetric algorithms (RS256/RS384/RS512) use the private key for signing;
  // for symmetric (HS256/HS384/HS512) fall back to the dedicated per-token secrets.
  const accessToken = jwt.sign(
    { ...baseClaims, jti: accessJti },
    _isAsymmetric ? signingKey : jwtConfig.accessSecret,
    buildOptions(null, jwtConfig.accessExpiry)
  );

  const refreshToken = jwt.sign(
    { sub: user._id.toString(), tenantId: user.tenantId, jti: refreshJti, sessionId },
    _isAsymmetric ? signingKey : jwtConfig.refreshSecret,
    buildOptions(null, jwtConfig.refreshExpiry)
  );

  const idToken = jwt.sign(
    {
      jti: idJti,
      sub: user._id.toString(),
      tenantId: user.tenantId,
      email: user.email,
      firstName: user.firstName,
      lastName:  user.lastName,
      username:  user.username,
      picture:   user.profilePicture?.url || null,
      phoneNumber: user.phoneNumber,
      role:      user.role?.name || null,
      emailVerified: user.emailVerified,
    },
    _isAsymmetric ? signingKey : jwtConfig.idSecret,
    buildOptions(null, jwtConfig.idExpiry)
  );

  return {
    accessToken,  accessJti,
    refreshToken, refreshJti,
    idToken,      idJti,
  };
};

/**
 * Verify an access (or id) token and return decoded payload, or throw.
 * Uses the public key for asymmetric algorithms, shared secret for HMAC.
 */
const verifyAccessToken = (token) =>
  jwt.verify(token, _isAsymmetric ? verifyingKey : jwtConfig.accessSecret, buildVerifyOptions());

/**
 * Verify a refresh token and return decoded payload, or throw.
 */
const verifyRefreshToken = (token) =>
  jwt.verify(token, _isAsymmetric ? verifyingKey : jwtConfig.refreshSecret, buildVerifyOptions());

/**
 * Set accessToken (header), refreshToken, and idToken as HttpOnly Secure cookies.
 */
const setCookiesOnHeader = (res, accessToken, refreshToken, idToken) => {
  const isProd  = env.IS_PROD;
  const base    = { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' };

  // Access token – short-lived, also returned in body
  res.cookie('accessToken',  accessToken,  { ...base, maxAge: 24 * 60 * 60 * 1000 });
  // Refresh token – 7-day HttpOnly cookie
  res.cookie('refreshToken', refreshToken, { ...base, maxAge: 7 * 24 * 60 * 60 * 1000 });
  // ID token – 30-day HttpOnly cookie
  res.cookie('idToken',      idToken,      { ...base, maxAge: 30 * 24 * 60 * 60 * 1000 });
};

/**
 * Clear all auth cookies on logout.
 */
const clearAuthCookies = (res) => {
  const base = { httpOnly: true, secure: env.IS_PROD, sameSite: 'strict', path: '/' };
  res.clearCookie('accessToken',  base);
  res.clearCookie('refreshToken', base);
  res.clearCookie('idToken',      base);
};

/**
 * Parse expiry string (e.g. '1d', '7d', '30d') to seconds.
 */
const expiryToSeconds = (expiry) => {
  const map = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  const match = String(expiry).match(/^(\d+)([smhdw])$/);
  if (!match) return 86400; // default 1 day
  return parseInt(match[1], 10) * (map[match[2]] || 86400);
};

module.exports = {
  generateTokens, verifyAccessToken, verifyRefreshToken,
  setCookiesOnHeader, clearAuthCookies, expiryToSeconds,
};
