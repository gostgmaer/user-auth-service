// src/middleware/authorize.js
// Permission-based authorization with resource/action-level access control
// and superadmin bypass.

const Role     = require('../models/Role');
const AppError = require('../utils/appError');
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

const authorize = (resource, action) => {
  return async (req, res, next) => {
    try {
      if (!req.user) return next(AppError.unauthorized('Authentication required'));

      // req.user is already loaded and role-populated by authMiddleware — no extra DB call needed.
      const user     = req.user;
      const tenantId = req.tenantId;

      // Superadmin bypass
      if (user.role?.name === 'super_admin') return next();

      // Settings resource — only super_admin
      if (resource === 'settings') {
        return next(AppError.forbidden('Only super_admin can access settings'));
      }

      // Load role with permissions (Redis-cached to avoid a per-request DB round-trip)
      const role = await getRoleWithPermissions(tenantId, user.role?._id);

      if (!role) return next(AppError.forbidden('Role not found or inactive'));

      // Check role permissions
      const hasPermission = role.permissions.some(
        (p) => p.resource === resource && (p.action === action || p.action === 'manage')
      );

      if (hasPermission) return next();

      return next(AppError.forbidden(`Access denied: requires ${action}:${resource}`));
    } catch (err) {
      return next(AppError.internal('Authorization check failed'));
    }
  };
};

module.exports = { authorize };
