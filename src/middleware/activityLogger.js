// src/middleware/activityLogger.js
const activityLogService = require('../services/activityLogService');

/**
 * Request-level activity logger: records method, path, status, duration,
 * user, and IP for every inbound request.
 * Non-blocking — errors are swallowed.
 */
const activityLogger = (req, res, next) => {
  const startAt = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startAt;
    // Fire-and-forget
    activityLogService
      .log(activityLogService.fromRequest(req, {
        operation:   getOperation(req.method),
        action:      `${req.method} ${req.originalUrl}`,
        description: `HTTP ${req.method} ${req.originalUrl} — ${res.statusCode} (${duration}ms)`,
        status:      res.statusCode < 400 ? 'success' : 'failure',
        metadata:    { statusCode: res.statusCode, duration },
      }))
      .catch(() => {});
  });

  next();
};

const getOperation = (method) => {
  switch (method.toUpperCase()) {
    case 'POST':   return 'create';
    case 'PUT':
    case 'PATCH':  return 'update';
    case 'DELETE': return 'delete';
    default:       return 'read';
  }
};

module.exports = { activityLogger };
