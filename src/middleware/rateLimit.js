// src/middleware/rateLimit.js
const rateLimit             = require('express-rate-limit');
const { RedisStore }        = require('rate-limit-redis');
const AppError              = require('../utils/appError');
const env                   = require('../config/env');
const { getRedisClient }    = require('../config/redis');
const { recordRateLimit }   = require('../utils/metrics');

const makeHandler = (message, limiterName) => (req, res) => {
  recordRateLimit(limiterName);
  res.status(429).json({
    success: false,
    statusCode: 429,
    message,
    error: { code: 'RATE_LIMIT_EXCEEDED' },
  });
};

/**
 * Returns a RedisStore for distributed rate limiting when Redis is configured,
 * otherwise returns undefined (express-rate-limit falls back to in-memory).
 * Using a unique prefix per limiter prevents key collisions across limit types.
 */
const makeStore = (prefix) => {
  const client = getRedisClient();
  if (!client) return undefined; // in-memory fallback for single-instance deployments
  return new RedisStore({
    prefix: `rl:${prefix}:`,
    sendCommand: (...args) => client.call(...args),
  });
};

const loginLimiter = rateLimit({
  windowMs: env.rateLimit.login.windowMs,
  max:      env.rateLimit.login.max,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => `${req.ip}:${req.tenantId || 'noTenant'}`,
  handler: makeHandler('Too many login attempts. Please try again in 15 minutes.', 'login'),
  store: makeStore('login'),
});

const registerLimiter = rateLimit({
  windowMs: env.rateLimit.register.windowMs,
  max:      env.rateLimit.register.max,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => `${req.ip}:${req.tenantId || 'noTenant'}`,
  handler: makeHandler('Too many registration attempts. Please try again later.', 'register'),
  store: makeStore('register'),
});

const otpLimiter = rateLimit({
  windowMs: env.rateLimit.otp.windowMs,
  max:      env.rateLimit.otp.max,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => `${req.ip}:${req.tenantId || 'noTenant'}`,
  handler: makeHandler('Too many OTP requests. Please try again later.', 'otp'),
  store: makeStore('otp'),
});

const resetLimiter = rateLimit({
  windowMs: env.rateLimit.reset.windowMs,
  max:      env.rateLimit.reset.max,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => `${req.ip}:${req.tenantId || 'noTenant'}`,
  handler: makeHandler('Too many password reset requests. Please try again later.', 'reset'),
  store: makeStore('reset'),
});

// Token verification endpoint: called by other microservices to validate JWTs.
// 120 req/min per IP is generous for service-to-service; still blocks brute-force enumeration.
const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      120,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => `${req.ip}:${req.tenantId || 'noTenant'}`,
  handler: makeHandler('Too many token verification requests.', 'verify'),
  store: makeStore('verify'),
});

// Token refresh endpoint: 30 refreshes per 15 min per IP is enough for legitimate
// multi-tab usage while blocking brute-force / flooding attacks.
const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      30,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => `${req.ip}:${req.tenantId || 'noTenant'}`,
  handler: makeHandler('Too many token refresh requests. Please try again later.', 'refresh'),
  store: makeStore('refresh'),
});

// ─── Global API limiter ───────────────────────────────────────────────────────
// Coarse backstop that protects every /api/* route from volumetric DoS.
// Fine-grained per-endpoint limiters above handle targeted abuse.
const globalApiLimiter = rateLimit({
  windowMs: 60 * 1000,         // 1 minute window
  max:      300,               // 300 requests/min per IP across ALL /api routes
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => req.ip,
  handler: makeHandler('API rate limit exceeded. Please slow down.', 'global'),
  store: makeStore('global'),
  // Skip health checks — they're not under /api but guard against misconfiguration
  skip: (req) => req.path === '/health' || req.path === '/health/live',
});

module.exports = { loginLimiter, registerLimiter, otpLimiter, resetLimiter, verifyLimiter, refreshLimiter, globalApiLimiter };
