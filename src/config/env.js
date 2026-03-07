// src/config/env.js
// Single source of truth for all configuration.
// All other files import from here — never from process.env directly.
// Env vars are validated and defaulted at startup by validateEnv.js.

const e = require('./validateEnv');

const env = {
  // ─── Application ──────────────────────────────────────────────────────────
  NODE_ENV:    e.NODE_ENV,
  PORT:        e.PORT,
  IS_PROD:     e.NODE_ENV === 'production',
  IS_DEV:      e.NODE_ENV === 'development',
  IS_TEST:     e.NODE_ENV === 'test',
  TRUST_PROXY: e.TRUST_PROXY,
  FRONTEND_URL: e.FRONTEND_URL || '',

  // ─── Database ─────────────────────────────────────────────────────────────
  MONGO_URI:     e.MONGO_URI,
  TENANCY_MODE:  e.TENANCY_MODE,

  // ─── Redis ────────────────────────────────────────────────────────────────
  REDIS_URL:               e.REDIS_URL || '',
  TOKEN_REVOCATION_STORE:  e.TOKEN_REVOCATION_STORE,

  // ─── JWT ──────────────────────────────────────────────────────────────────
  jwt: {
    accessSecret:  e.JWT_ACCESS_SECRET,
    refreshSecret: e.JWT_REFRESH_SECRET,
    idSecret:      e.JWT_ID_SECRET,
    accessExpiry:  e.JWT_ACCESS_EXPIRY,
    refreshExpiry: e.JWT_REFRESH_EXPIRY,
    idExpiry:      e.JWT_ID_EXPIRY,
    issuer:        e.JWT_ISSUER,
    audience:      e.JWT_AUDIENCE,
    algorithm:     e.JWT_ALGORITHM || 'HS256',
    privateKeyPath: e.JWT_PRIVATE_KEY_PATH || null,
    publicKeyPath:  e.JWT_PUBLIC_KEY_PATH  || null,
  },

  // ─── Security ─────────────────────────────────────────────────────────────
  BCRYPT_ROUNDS:              e.BCRYPT_ROUNDS,
  MAX_LOGIN_ATTEMPTS:         e.MAX_LOGIN_ATTEMPTS,
  LOCK_WINDOW_MINUTES:        e.LOCK_WINDOW_MINUTES,
  LOCK_WINDOW_MS:             e.LOCK_WINDOW_MINUTES * 60 * 1000,
  EMAIL_VERIFY_EXPIRY_HOURS:  e.EMAIL_VERIFY_EXPIRY_HOURS,
  PASSWORD_RESET_EXPIRY_HOURS: e.PASSWORD_RESET_EXPIRY_HOURS,

  // ─── OTP / MFA ────────────────────────────────────────────────────────────
  OTP_METHOD:         e.OTP_METHOD,
  OTP_EXPIRY_MINUTES: e.OTP_EXPIRY_MINUTES,
  OTP_EXPIRY_MS:      e.OTP_EXPIRY_MINUTES * 60 * 1000,
  OTP_LENGTH:         e.OTP_LENGTH,
  TOTP_ISSUER:        e.TOTP_ISSUER,
  ENABLE_OTP_VERIFICATION: e.ENABLE_OTP_VERIFICATION === 'true',

  // ─── Email ────────────────────────────────────────────────────────────────
  EMAIL_SERVICE_URL: e.EMAIL_SERVICE_URL,
  EMAIL_FROM_ADDRESS: e.EMAIL_FROM_ADDRESS || '',
  EMAIL_FROM_NAME:    e.EMAIL_FROM_NAME || '',

  // ─── CORS ─────────────────────────────────────────────────────────────────
  CORS_ORIGIN: e.CORS_ORIGIN,

  // ─── Rate limiting ────────────────────────────────────────────────────────
  // Values are already typed numbers via Joi; no parseInt needed.
  rateLimit: {
    login:    { windowMs: e.LOGIN_RATE_WINDOW_MS,    max: e.LOGIN_RATE_LIMIT    },
    register: { windowMs: e.REGISTER_RATE_WINDOW_MS, max: e.REGISTER_RATE_LIMIT },
    otp:      { windowMs: e.OTP_RATE_WINDOW_MS,      max: e.OTP_RATE_LIMIT      },
    reset:    { windowMs: e.RESET_RATE_WINDOW_MS,    max: e.RESET_RATE_LIMIT    },
  },

  // ─── Logging ──────────────────────────────────────────────────────────────
  LOG_LEVEL:  e.LOG_LEVEL,
  LOG_FORMAT: e.LOG_FORMAT,
};

module.exports = env;
