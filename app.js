// app.js — Express application factory
'use strict';

const express          = require('express');
const helmet           = require('helmet');
const cors             = require('cors');
const cookieParser     = require('cookie-parser');
const mongoSanitize    = require('express-mongo-sanitize');
const morgan           = require('morgan');
const hpp              = require('hpp');

const compression      = require('./src/middleware/compression.middleware');
const { sanitizeInput } = require('./src/middleware/sanitization');
const { loggerMiddleware } = require('./src/middleware/loggerMiddleware');
const { tenantMiddleware } = require('./src/middleware/tenant');
const { errorHandler }     = require('./src/middleware/errorHandler');
const requestTimeout   = require('./src/middleware/requestTimeout');
const { globalApiLimiter } = require('./src/middleware/rateLimit');
const { metricsMiddleware } = require('./src/utils/metrics');
const logger           = require('./src/utils/logger');

// Eager-register all Mongoose models before any route handler runs
require('./src/models/index');

const healthRoutes      = require('./src/routes/healthRoutes');
const authRoutes        = require('./src/routes/authRoutes');
const socialAuthRoutes  = require('./src/routes/socialAuthRoutes');
const adminRoutes       = require('./src/routes/adminRoutes');
const internalRoutes    = require('./src/routes/internalRoutes');

const app = express();

// Trust the first proxy in the chain (load balancer / API gateway) — required for req.ip accuracy
app.set('trust proxy', parseInt(process.env.TRUST_PROXY || '1', 10));

// ─── Security headers ─────────────────────────────────────────────────────────
app.use(helmet({
  // Content-Security-Policy: restrict sources; API-gateway may override
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'none'"],
      scriptSrc:      ["'none'"],
      objectSrc:      ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginResourcePolicy:   { policy: 'cross-origin' },
  crossOriginOpenerPolicy:     { policy: 'same-origin' },
  originAgentCluster:          true,
  strictTransportSecurity:     { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy:              { policy: 'strict-origin-when-cross-origin' },
  xContentTypeOptions:         true,
  xFrameOptions:               { action: 'deny' },
}));

// ─── CORS ─────────────────────────────────────────────────────────────────────
const corsOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3000').split(',').map((s) => s.trim());
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || corsOrigins.includes('*') || corsOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
  methods:  ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-Id', 'X-Request-Id'],
  exposedHeaders: ['X-Request-Id'],
}));

// ─── Compression ──────────────────────────────────────────────────────────────
app.use(compression);

// ─── Body parsers ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

// ─── HTTP Parameter Pollution protection ─────────────────────────────────────
// Strips duplicate query params (e.g. ?role=admin&role=super_admin) to the last value.
// Whitelist fields that legitimately accept arrays.
app.use(hpp({ whitelist: ['sort', 'fields', 'ids'] }));

// ─── Sanitization ─────────────────────────────────────────────────────────────
// express-mongo-sanitize@2.2.0 tries to assign req.query which is a read-only
// getter in newer Node/router versions. Sanitize only body and params manually.
app.use((req, _res, next) => {
  if (req.body)   req.body   = mongoSanitize.sanitize(req.body,   { replaceWith: '_' });
  if (req.params) req.params = mongoSanitize.sanitize(req.params, { replaceWith: '_' });
  next();
});
app.use(sanitizeInput);

// ─── Request ID ───────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  req.requestId = req.headers['x-request-id'] || require('crypto').randomUUID();
  next();
});

// ─── Response envelope ────────────────────────────────────────────────────────
// Injects: timestamp, requestId, statusCode, status into every JSON response.
// Also serialises _id → id (string), strips __v, strips null values, sets headers.
app.use((req, res, next) => {
  res.setHeader('X-Request-ID', req.requestId);
  const _json = res.json.bind(res);
  res.json = function (body) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (body !== null && body !== undefined && typeof body === 'object' && !Array.isArray(body)) {
      body.timestamp  = new Date().toISOString();
      body.requestId  = req.requestId;
      body.statusCode = res.statusCode;
      body.status     = res.statusCode < 400 ? 'success' : 'error';
    }
    return _json(_cleanResponse(body));
  };
  next();
});

// ─── Per-request timeout (30 s hard limit) ────────────────────────────────────
app.use(requestTimeout(30_000));

// ─── Prometheus metrics instrumentation ──────────────────────────────────────
app.use(metricsMiddleware);

// ─── HTTP logging ─────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined', {
    stream: { write: (msg) => logger.http(msg.trim()) },
    skip:   (req) => req.path === '/health' || req.path === '/health/live',
  }));
  app.use(loggerMiddleware);
}

// ─── Health (no tenant required) ─────────────────────────────────────────────
app.use('/health', healthRoutes);

// ─── Global API rate limiter (coarse backstop before tenant resolution) ───────
app.use('/api', globalApiLimiter);

// ─── Tenant extraction (required for all /api routes) ────────────────────────
// NOTE: tenant middleware is applied here so Routes don't need to include it
app.use('/api', tenantMiddleware);

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth',         authRoutes);
app.use('/api/auth/social',  socialAuthRoutes);
app.use('/api/admin',        adminRoutes);
app.use('/api/internal',     internalRoutes);

// ─── 404 handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error:   'NOT_FOUND',
    message: `Route ${req.method} ${req.originalUrl} not found`,
  });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use(errorHandler);

module.exports = app;

// ─── Response transform ───────────────────────────────────────────────────────
// Serialises Mongoose docs (_id → id, drops __v) and strips null values.
function _cleanResponse(val) {
  if (val === null || val === undefined) return undefined;
  if (typeof val !== 'object') return val;
  if (val instanceof Date) return val;
  if (Buffer.isBuffer(val)) return val;
  if (Array.isArray(val)) return val.map(_cleanResponse).filter(v => v !== undefined);
  const src = typeof val.toJSON === 'function' ? val.toJSON() : val;
  if (typeof src !== 'object' || src === null) return src;
  const out = {};
  for (const key of Object.keys(src)) {
    if (key === '__v' || key === '_id' || key === 'id' ||
        key === 'isDeleted' || key === 'deletedAt' ||
        key === 'created_by' || key === 'updated_by' || key === 'deleted_by') continue;
    const v = _cleanResponse(src[key]);
    if (v !== undefined) out[key] = v;
  }
  const rawId = src.id !== undefined ? src.id : src._id;
  if (rawId !== undefined) out.id = String(rawId);
  return out;
}
