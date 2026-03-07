// src/services/tokenRevocationService.js
/**
 * Token Revocation Service
 * Supports two adapters: 'db' (default) and 'redis'.
 * Adapter is selected by TOKEN_REVOCATION_STORE env variable.
 */

const env   = require('../config/env');

const STORE = env.TOKEN_REVOCATION_STORE;

// ─── DB adapter ───────────────────────────────────────────────────────────────
const TokenBlacklist = require('../models/TokenBlacklist');

const _dbRevoke = async (jti, tenantId, userId, expiresAt, reason = 'logout') => {
  await TokenBlacklist.findOneAndUpdate(
    { jti, tenantId },
    { jti, tenantId, userId, reason, expiresAt },
    { upsert: true, new: true }
  );
};

const _dbIsRevoked = async (jti, tenantId) => {
  return TokenBlacklist.exists({ jti, tenantId });
};

// ─── Redis adapter ────────────────────────────────────────────────────────────
let _redis = null;
const _getRedis = () => {
  if (!_redis) _redis = require('../config/redis').getRedisClient();
  return _redis;
};

const _redisRevoke = async (jti, tenantId, ttlSeconds) => {
  const client = _getRedis();
  if (!client) return _dbRevoke(jti, tenantId, null, new Date(Date.now() + ttlSeconds * 1000));
  await client.set(`revoked:${tenantId}:${jti}`, '1', 'EX', ttlSeconds);
};

const _redisIsRevoked = async (jti, tenantId) => {
  const client = _getRedis();
  if (!client) return _dbIsRevoked(jti, tenantId);
  const val = await client.get(`revoked:${tenantId}:${jti}`);
  return val !== null;
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Revoke a token by jti.
 * @param {string} jti         - JWT ID claim
 * @param {string} tenantId    - Tenant scope
 * @param {string} userId      - User ID (for audit)
 * @param {number} ttlSeconds  - Seconds until the token naturally expires
 * @param {string} reason      - Revocation reason
 */
const revokeToken = async (jti, tenantId, userId, ttlSeconds, reason = 'logout') => {
  if (STORE === 'redis') {
    return _redisRevoke(jti, tenantId, ttlSeconds);
  }
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  return _dbRevoke(jti, tenantId, userId, expiresAt, reason);
};

/**
 * Check if a token has been revoked.
 */
const isTokenRevoked = async (jti, tenantId) => {
  if (STORE === 'redis') return _redisIsRevoked(jti, tenantId);
  return _dbIsRevoked(jti, tenantId);
};

/**
 * Revoke all active tokens for a user (logout all sessions).
 * Adds all jti values from activeSessions to the blacklist.
 */
const revokeAllUserTokens = async (user, reason = 'revoked_all') => {
  if (!user.refreshTokens || user.refreshTokens.length === 0) return;
  const now = Date.now();

  await Promise.all(
    user.refreshTokens
      .filter((rt) => rt.isActive && rt.expiresAt > now)
      .map((rt) => {
        const ttl = Math.floor((rt.expiresAt - now) / 1000);
        return revokeToken(rt.jti, user.tenantId, user._id.toString(), ttl, reason);
      })
  );

  // Mark all as inactive
  user.refreshTokens.forEach((rt) => (rt.isActive = false));
  user.activeSessions.forEach((s)  => (s.isActive = false));
  await user.save();
};

module.exports = { revokeToken, isTokenRevoked, revokeAllUserTokens };
