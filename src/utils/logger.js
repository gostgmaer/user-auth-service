// src/utils/logger.js
'use strict';

const winston    = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path       = require('path');
const env        = require('../config/env');

// ─── Formats ─────────────────────────────────────────────────────────────────
const jsonFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json(),
);

const prettyFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta, null, 0) : '';
    return `${timestamp} [${level}]: ${message}${metaStr}`;
  }),
);

// ─── Transports ───────────────────────────────────────────────────────────────
const transports = [];

// Console — always present
transports.push(
  new winston.transports.Console({
    format: env.LOG_FORMAT === 'pretty' || env.IS_DEV ? prettyFormat : jsonFormat,
  }),
);

// File transports — only in production/staging to avoid filling dev disk
if (env.IS_PROD || process.env.LOG_TO_FILE === 'true') {
  const logDir = path.resolve(process.env.LOG_DIR || 'logs');

  // Combined (info+) — rotated daily, compressed, kept 14 days
  transports.push(
    new DailyRotateFile({
      filename:    path.join(logDir, 'combined-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize:     '20m',
      maxFiles:    '14d',
      level:       'http',
      format:      jsonFormat,
      // Don't crash the app if the log directory doesn't exist yet
      createSymlink: false,
      auditFile:   path.join(logDir, '.combined-audit.json'),
    }),
  );

  // Error-only — kept 30 days for post-incident forensics
  transports.push(
    new DailyRotateFile({
      filename:    path.join(logDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize:     '10m',
      maxFiles:    '30d',
      level:       'error',
      format:      jsonFormat,
      createSymlink: false,
      auditFile:   path.join(logDir, '.error-audit.json'),
    }),
  );
}

// ─── Logger instance ─────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level:      env.LOG_LEVEL || 'info',
  defaultMeta: { service: 'user-auth-service', pid: process.pid },
  transports,
  // Do NOT exit on handled exceptions — let our uncaughtException handler do it
  exitOnError: false,
});

// Forward unhandled exceptions and rejections to the logger before Winston shuts
if (env.IS_PROD) {
  logger.exceptions.handle(
    new DailyRotateFile({
      filename:  path.join(process.env.LOG_DIR || 'logs', 'exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxFiles:  '30d',
      format:    jsonFormat,
    }),
  );
}

module.exports = logger;
