// src/middleware/tenant.js
const AppError = require('../utils/appError');

const TENANT_PATTERN = /^[a-z0-9_-]{3,64}$/;

const tenantMiddleware = (req, res, next) => {
  const tenantId = req.headers['x-tenant-id'];

  if (!tenantId) {
    return next(AppError.badRequest('Missing X-Tenant-Id header'));
  }

  if (!TENANT_PATTERN.test(tenantId)) {
    return next(AppError.badRequest('Invalid X-Tenant-Id format. Must match ^[a-z0-9_-]{3,64}$'));
  }

  req.tenantId = tenantId;
  next();
};

module.exports = { tenantMiddleware };
