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

// ─── Startup secret guard ─────────────────────────────────────────────────────
// Fail immediately at service startup — never let the service run with weak or
// missing secrets. This prevents silent failures from jwt.sign accepting empty strings.
;(() => {
  if (!_isAsymmetric) {
    const required = [
      ['JWT_ACCESS_SECRET',  jwtConfig.accessSecret],
      ['JWT_REFRESH_SECRET', jwtConfig.refreshSecret],
      ['JWT_ID_SECRET',      jwtConfig.idSecret],
    ];
    for (const [name, value] of required) {
      if (!value || typeof value !== 'string' || value.trim().length < 32) {
        throw new Error(`[tokenService] ${name} is missing or too short (min 32 chars). Refusing to start.`);
      }
    }
    if (jwtConfig.accessSecret === jwtConfig.refreshSecret) {
      throw new Error('[tokenService] JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be different. Using the same secret for both token types breaks token-type isolation.');
    }
    if (jwtConfig.accessSecret === jwtConfig.idSecret || jwtConfig.refreshSecret === jwtConfig.idSecret) {
      throw new Error('[tokenService] JWT_ID_SECRET must be different from JWT_ACCESS_SECRET and JWT_REFRESH_SECRET.');
    }
  } else {
    if (!signingKey || !verifyingKey) {
      throw new Error('[tokenService] Asymmetric JWT keys (private/public) are missing or failed to load. Refusing to start.');
    }
  }
})();

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
    { ...baseClaims, jti: accessJti, token_type: 'access' },
    _isAsymmetric ? signingKey : jwtConfig.accessSecret,
    buildOptions(null, jwtConfig.accessExpiry)
  );

  const refreshToken = jwt.sign(
    { sub: user._id.toString(), tenantId: user.tenantId, jti: refreshJti, sessionId, token_type: 'refresh' },
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
 * Verify an access token and return decoded payload, or throw.
 * Also enforces token_type === 'access' to block refresh tokens being used as bearer tokens.
 */
const verifyAccessToken = (token) => {
  const decoded = jwt.verify(token, _isAsymmetric ? verifyingKey : jwtConfig.accessSecret, buildVerifyOptions());
  if (decoded.token_type !== 'access') {
    throw new jwt.JsonWebTokenError('Invalid token type: expected access token');
  }
  return decoded;
};

/**
 * Verify a refresh token and return decoded payload, or throw.
 * Also enforces token_type === 'refresh' to block access tokens being used for refresh.
 */
const verifyRefreshToken = (token) => {
  const decoded = jwt.verify(token, _isAsymmetric ? verifyingKey : jwtConfig.refreshSecret, buildVerifyOptions());
  if (decoded.token_type !== 'refresh') {
    throw new jwt.JsonWebTokenError('Invalid token type: expected refresh token');
  }
  return decoded;
};

/**
 * Parse expiry string (e.g. '15m', '7d', '30d') to seconds.
 */
const expiryToSeconds = (expiry) => {
  const map = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  const match = String(expiry).match(/^(\d+)([smhdw])$/);
  if (!match) return 86400; // default 1 day
  return parseInt(match[1], 10) * (map[match[2]] || 86400);
};

/**
 * Set accessToken, refreshToken, and idToken as HttpOnly Secure cookies.
 * maxAge is derived from the JWT expiry config so cookies always match token lifetime.
 */
const setCookiesOnHeader = (res, accessToken, refreshToken, idToken) => {
  const isProd  = env.IS_PROD;
  const base    = { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' };

  res.cookie('accessToken',  accessToken,  { ...base, maxAge: expiryToSeconds(jwtConfig.accessExpiry)  * 1000 });
  res.cookie('refreshToken', refreshToken, { ...base, maxAge: expiryToSeconds(jwtConfig.refreshExpiry) * 1000 });
  res.cookie('idToken',      idToken,      { ...base, maxAge: expiryToSeconds(jwtConfig.idExpiry)      * 1000 });
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

module.exports = {
  generateTokens, verifyAccessToken, verifyRefreshToken,
  setCookiesOnHeader, clearAuthCookies, expiryToSeconds,
};
