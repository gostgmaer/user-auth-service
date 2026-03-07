// src/config/validateEnv.js
require('dotenv').config();
const Joi = require('joi');

const schema = Joi.object({
  NODE_ENV:               Joi.string().valid('development', 'production', 'test').default('development'),
  PORT:                   Joi.number().default(4002),
  MONGO_URI:              Joi.string().required(),
  TENANCY_MODE:           Joi.string().valid('shared', 'per-db').default('shared'),
  JWT_ACCESS_SECRET:      Joi.string().min(32).required(),
  JWT_REFRESH_SECRET:     Joi.string().min(32).required(),
  JWT_ID_SECRET:          Joi.string().min(32).required(),
  JWT_ACCESS_EXPIRY:      Joi.string().default('15m'),
  JWT_REFRESH_EXPIRY:     Joi.string().default('7d'),
  JWT_ID_EXPIRY:          Joi.string().default('30d'),
  JWT_ISSUER:             Joi.string().required(),
  JWT_AUDIENCE:           Joi.string().required(),
  BCRYPT_ROUNDS:          Joi.number().min(10).max(14).default(12),
  MAX_LOGIN_ATTEMPTS:     Joi.number().default(5),
  LOCK_WINDOW_MINUTES:    Joi.number().default(15),
  OTP_METHOD:             Joi.string().valid('totp', 'email', 'sms').default('email'),
  OTP_EXPIRY_MINUTES:     Joi.number().default(10),
  OTP_LENGTH:             Joi.number().default(6),
  TOTP_ISSUER:            Joi.string().required(),
  EMAIL_VERIFY_EXPIRY_HOURS:   Joi.number().default(24),
  PASSWORD_RESET_EXPIRY_HOURS: Joi.number().default(1),
  EMAIL_SERVICE_URL:      Joi.string().uri().required(),
  TOKEN_REVOCATION_STORE: Joi.string().valid('db', 'redis').default('db'),
  REDIS_URL:              Joi.when('TOKEN_REVOCATION_STORE', {
    is: 'redis',
    then: Joi.string().required(),
    otherwise: Joi.string().optional(),
  }),
  CORS_ORIGIN:            Joi.string().required(),
  LOG_LEVEL:              Joi.string().valid('error', 'warn', 'info', 'http', 'debug').default('info'),
  LOG_FORMAT:             Joi.string().valid('json', 'pretty').default('json'),
  LOG_TO_FILE:            Joi.string().valid('true', 'false').default('false'),
  LOG_DIR:                Joi.string().optional().allow('').default('logs'),
  TRUST_PROXY:            Joi.number().default(1),
  // ─── Frontend & OTP ─────────────────────────────────────────────────────
  FRONTEND_URL:           Joi.string().uri().optional().allow(''),
  ENABLE_OTP_VERIFICATION: Joi.string().valid('true', 'false').default('false'),
  // ─── Email sender identity ───────────────────────────────────────────────
  EMAIL_FROM_ADDRESS:     Joi.string().email().optional().allow(''),
  EMAIL_FROM_NAME:        Joi.string().optional().allow(''),
  // ─── JWT optional / asymmetric ───────────────────────────────────────────
  JWT_ALGORITHM:          Joi.string().valid('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512').default('HS256'),
  JWT_PRIVATE_KEY_PATH:   Joi.string().optional().allow(''),
  JWT_PUBLIC_KEY_PATH:    Joi.string().optional().allow(''),
  // ─── Rate-limit tuning ───────────────────────────────────────────────────
  // Validated as numbers here so a typo (e.g. LOGIN_RATE_LIMIT=abc) fails fast
  // at startup rather than silently collapsing to NaN and disabling rate limiting.
  LOGIN_RATE_LIMIT:        Joi.number().integer().positive().default(10),
  LOGIN_RATE_WINDOW_MS:    Joi.number().integer().positive().default(900000),
  REGISTER_RATE_LIMIT:     Joi.number().integer().positive().default(5),
  REGISTER_RATE_WINDOW_MS: Joi.number().integer().positive().default(3600000),
  OTP_RATE_LIMIT:          Joi.number().integer().positive().default(5),
  OTP_RATE_WINDOW_MS:      Joi.number().integer().positive().default(3600000),
  RESET_RATE_LIMIT:        Joi.number().integer().positive().default(3),
  RESET_RATE_WINDOW_MS:    Joi.number().integer().positive().default(3600000),
  // ─── Observability ───────────────────────────────────────────────────────
  // Bearer token required to access GET /health/metrics (Prometheus scrape endpoint).
  // Set to a strong random value in production.
  METRICS_SECRET:          Joi.string().min(16).optional().allow(''),
  // ─── Background jobs ─────────────────────────────────────────────────────
  CLEANUP_ENABLED:         Joi.string().valid('true', 'false').default('true'),
  // ─── PM2 / cluster tuning ────────────────────────────────────────────────
  WEB_CONCURRENCY:         Joi.alternatives().try(Joi.number().integer().min(1), Joi.string().valid('max')).optional(),
}).unknown(true);

const { error, value } = schema.validate(process.env);
if (error) {
  console.error('❌ Environment validation failed:', error.message);
  process.exit(1);
}

module.exports = value;
