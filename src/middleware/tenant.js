// src/middleware/tenant.js
const AppError = require('../utils/appError');

const TENANT_PATTERN = /^[a-z0-9_-]{3,64}$/;

// TENANCY_ENABLED=true  → x-tenant-id (or DEFAULT_TENANT_ID) is enforced; 400 if missing.
// TENANCY_ENABLED=false → tenant is optional; services run without tenant scoping (req.tenantId = null).
const TENANCY_ENABLED   = process.env.TENANCY_ENABLED === 'true';
const DEFAULT_TENANT_ID = process.env.DEFAULT_TENANT_ID
  ? process.env.DEFAULT_TENANT_ID.trim()
  : null;

const tenantMiddleware = (req, res, next) => {
  const tenantId = (req.headers['x-tenant-id'] || DEFAULT_TENANT_ID || '').trim();

  if (!tenantId) {
    if (TENANCY_ENABLED) {
      return next(AppError.badRequest(
        'Missing X-Tenant-Id header. Set DEFAULT_TENANT_ID in the service env or pass the header explicitly.'
      ));
    }
    // Non-tenanted mode — continue without tenant scoping.
    req.tenantId = null;
    return next();
  }

  if (!TENANT_PATTERN.test(tenantId)) {
    return next(AppError.badRequest('Invalid X-Tenant-Id format. Must match ^[a-z0-9_-]{3,64}$'));
  }

  req.tenantId = tenantId;
  next();
};

module.exports = { tenantMiddleware };
