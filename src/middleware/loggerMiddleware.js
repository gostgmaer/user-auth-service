// src/middleware/loggerMiddleware.js
const UAParser = require('ua-parser-js');
const logger   = require('../utils/logger');

/**
 * Structured HTTP logger with user-agent parsing.
 * Non-blocking — geolocation is skipped to avoid external HTTP calls per request.
 */
const loggerMiddleware = (req, res, next) => {
  const startAt = Date.now();

  res.on('finish', () => {
    const ua       = req.headers['user-agent'] || '';
    const parser   = new UAParser(ua);
    const result   = parser.getResult();
    const duration = Date.now() - startAt;

    logger.http('HTTP request', {
      method:   req.method,
      url:      req.originalUrl,
      status:   res.statusCode,
      duration: `${duration}ms`,
      ip:       req.ip,
      tenantId: req.tenantId || null,
      userId:   req.user?._id?.toString() || null,
      browser:  result.browser.name || 'unknown',
      os:       result.os.name || 'unknown',
      device:   result.device.type || 'desktop',
    });
  });

  next();
};

module.exports = { loggerMiddleware };
