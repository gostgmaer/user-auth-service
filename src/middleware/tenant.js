// src/middleware/tenant.js
const AppError = require('../utils/appError');

const TENANT_PATTERN = /^[a-z0-9_-]{3,64}$/;

// Tenant enforcement switch.
const TENANCY_ENABLED = process.env.TENANCY_ENABLED === 'true';
// Tenant is resolved from x-tenant-id or DEFAULT_TENANT_ID fallback when tenancy is enabled.
const DEFAULT_TENANT_ID = process.env.DEFAULT_TENANT_ID ? process.env.DEFAULT_TENANT_ID.trim() : "easydev";

const tenantMiddleware = (req, res, next) => {
  if (!TENANCY_ENABLED) {
		req.tenantId = null;
		return next();
	}

  const tenantId = (req.headers['x-tenant-id'] || DEFAULT_TENANT_ID || '').trim();

  if (!tenantId) {
		// Fallback tenant when no header is provided.
		req.tenantId = "easydev";
		return next();
	}

  if (!TENANT_PATTERN.test(tenantId)) {
    return next(AppError.badRequest('Invalid X-Tenant-Id format. Must match ^[a-z0-9_-]{3,64}$'));
  }

  req.tenantId = tenantId;
  next();
};

module.exports = { tenantMiddleware };
