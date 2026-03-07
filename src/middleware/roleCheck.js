// src/middleware/roleCheck.js
// RBAC role validation — rejects with 403 for unauthorized roles.

const AppError = require('../utils/appError');

const roleCheck = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) return next(AppError.unauthorized('Authentication required'));

    const userRole = req.user.role?.name;
    const hasRole  = allowedRoles.includes(userRole);

    if (!hasRole) {
      return next(
        AppError.forbidden(`Access denied. Required role(s): ${allowedRoles.join(', ')}`)
      );
    }
    next();
  };
};

module.exports = roleCheck;
