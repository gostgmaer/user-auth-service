// src/middleware/permission.js
// Granular permission checker with multi-permission support.

const AppError = require('../utils/appError');
const Role     = require('../models/Role');
const { getRedisClient } = require('../config/redis');

const ROLE_CACHE_TTL = 60; // seconds

/**
 * Fetch a role (with permissions populated) using Redis as a 60-second cache.
 * Falls back to MongoDB on cache miss or Redis unavailability.
 */
const getRoleWithPermissions = async (tenantId, roleId) => {
  const client   = getRedisClient();
  const cacheKey = `role_perms:${tenantId}:${roleId}`;

  if (client) {
    try {
      const cached = await client.get(cacheKey);
      if (cached) return JSON.parse(cached);
    } catch { /* fallthrough to DB on cache error */ }
  }

  const role = await Role
    .findOne({ tenantId, _id: roleId, isActive: true, isDeleted: false })
    .populate('permissions')
    .lean();

  if (role && client) {
    try { await client.set(cacheKey, JSON.stringify(role), 'EX', ROLE_CACHE_TTL); } catch { /* non-fatal */ }
  }

  return role;
};

/**
 * Check that the authenticated user holds at least one of the given permission keys.
 * Admin + superadmin bypass all permission checks.
 * @param {...string} permissionKeys - Format: 'action:resource' (e.g. 'read:users')
 */
const hasPermission = (...permissionKeys) => {
  return async (req, res, next) => {
    try {
      if (!req.user) return next(AppError.unauthorized('Authentication required'));

      // Admin / superadmin bypass
      if (['super_admin', 'admin'].includes(req.user.role?.name)) return next();

      const tenantId = req.tenantId;
      const role     = await getRoleWithPermissions(tenantId, req.user.role?._id);

      if (!role) return next(AppError.forbidden('Role not found'));

      const roleKeys = (role.permissions || []).map((p) => p.key);

      const allowed = permissionKeys.some((key) => roleKeys.includes(key));
      if (!allowed) {
        return next(AppError.forbidden(`Missing required permission: ${permissionKeys.join(' | ')}`));
      }
      next();
    } catch (err) {
      return next(AppError.internal('Permission check failed'));
    }
  };
};

module.exports = { hasPermission };
