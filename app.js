// app.js — Express application factory
'use strict';

const express          = require('express');
const helmet           = require('helmet');
const cors             = require('cors');
const cookieParser     = require('cookie-parser');
const mongoSanitize    = require('express-mongo-sanitize');
const morgan           = require('morgan');

const compression      = require('./src/middleware/compression.middleware');
const { sanitizeInput } = require('./src/middleware/sanitization');
const { loggerMiddleware } = require('./src/middleware/loggerMiddleware');
const { tenantMiddleware } = require('./src/middleware/tenant');
const { errorHandler }     = require('./src/middleware/errorHandler');
const logger           = require('./src/utils/logger');

const healthRoutes      = require('./src/routes/healthRoutes');
const authRoutes        = require('./src/routes/authRoutes');
const socialAuthRoutes  = require('./src/routes/socialAuthRoutes');
const adminRoutes       = require('./src/routes/adminRoutes');

const app = express();

// Trust the first proxy in the chain (load balancer / API gateway) — required for req.ip accuracy
app.set('trust proxy', parseInt(process.env.TRUST_PROXY || '1', 10));

// ─── Security headers ─────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // managed by API gateway
  crossOriginResourcePolicy: { policy: 'cross-origin' },
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

// ─── Sanitization ─────────────────────────────────────────────────────────────
app.use(mongoSanitize({ replaceWith: '_' }));
app.use(sanitizeInput);

// ─── Request ID ───────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  req.requestId = req.headers['x-request-id'] || require('crypto').randomUUID();
  next();
});

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

// ─── Tenant extraction (required for all /api routes) ────────────────────────
// NOTE: tenant middleware is applied here so Routes don't need to include it
app.use('/api', tenantMiddleware);

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth',         authRoutes);
app.use('/api/auth/social',  socialAuthRoutes);
app.use('/api/admin',        adminRoutes);

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
