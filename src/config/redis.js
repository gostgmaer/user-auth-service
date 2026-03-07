// src/config/redis.js
const Redis = require('ioredis');
const logger = require('../utils/logger');

const env = require('./env');

let redisClient = null;

const getRedisClient = () => {
  if (redisClient) return redisClient;

  if (env.TOKEN_REVOCATION_STORE !== 'redis') {
    return null;
  }

  redisClient = new Redis(env.REDIS_URL, {
    // ── Reliability ────────────────────────────────────────────────────────
    maxRetriesPerRequest: 3,
    lazyConnect:          true,
    enableOfflineQueue:   false,          // fail fast — don't queue commands while disconnected
    connectTimeout:       5000,
    commandTimeout:       3000,
    keepAlive:            30000,          // TCP keepalive every 30 s (prevents silent NAT drops)
    // ── Reconnect ─────────────────────────────────────────────────────────
    retryStrategy: (times) => {
      if (times > 8) {
        logger.error('Redis: too many reconnect attempts — giving up');
        return null;                      // stop retrying; in-memory failover kicks in
      }
      const delay = Math.min(times * 200, 3000);
      logger.warn(`Redis: reconnecting in ${delay}ms (attempt ${times})`);
      return delay;
    },
    // ── TLS (uncomment for Redis TLS / Redis Cloud) ────────────────────────
    // tls: env.IS_PROD ? {} : undefined,
  });

  redisClient.on('connect',       () => logger.info('Redis connected'));
  redisClient.on('ready',         () => logger.info('Redis ready'));
  redisClient.on('reconnecting',  () => logger.warn('Redis reconnecting…'));
  redisClient.on('error',         (err) => logger.warn('Redis error (non-fatal)', { message: err.message }));
  redisClient.on('close',         () => logger.warn('Redis connection closed'));

  return redisClient;
};

const isRedisReady = async () => {
  const client = getRedisClient();
  if (!client) return false;
  try {
    const pong = await client.ping();
    return pong === 'PONG';
  } catch {
    return false;
  }
};

/**
 * Gracefully close the Redis connection during application shutdown.
 * Called from server.js shutdown handler — must NOT be called before all
 * in-flight Redis commands have completed.
 */
const disconnectRedis = async () => {
  if (!redisClient) return;
  try {
    await redisClient.quit();
    logger.info('Redis disconnected gracefully');
  } catch {
    redisClient.disconnect();            // force-close if quit times out
  } finally {
    redisClient = null;
  }
};

module.exports = { getRedisClient, isRedisReady, disconnectRedis };
