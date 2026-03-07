// src/utils/logger.js
const winston = require('winston');
const env = require('../config/env');

const logger = winston.createLogger({
  level: env.LOG_LEVEL || 'info',
  format:
    env.LOG_FORMAT === 'pretty' || env.IS_DEV
      ? winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
          winston.format.printf(({ timestamp, level, message, ...meta }) => {
            const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
            return `${timestamp} [${level}]: ${message}${metaStr}`;
          })
        )
      : winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

module.exports = logger;
