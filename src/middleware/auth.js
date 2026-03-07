// src/middleware/auth.js
const User              = require('../models/User');
const { verifyAccessToken } = require('../services/tokenService');
const { isTokenRevoked }    = require('../services/tokenRevocationService');
const AppError = require('../utils/appError');
const DeviceDetector   = require('../services/deviceDetector');

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(AppError.unauthorized('No authentication token provided'));
    }

    const token = authHeader.split(' ')[1];
    if (!token) return next(AppError.unauthorized('Invalid token format'));

    // 1. Verify JWT signature + claims
    let decoded;
    try {
      decoded = verifyAccessToken(token);
    } catch (jwtError) {
      if (jwtError.name === 'TokenExpiredError') {
        return next(AppError.unauthorized('Token has expired', 'TOKEN_EXPIRED'));
      }
      return next(AppError.unauthorized('Invalid token'));
    }

    // 2. Check token revocation (blacklist)
    const tenantId = req.tenantId || decoded.tenantId;
    const revoked  = await isTokenRevoked(decoded.jti, tenantId);
    if (revoked) {
      return next(AppError.unauthorized('Token has been revoked', 'TOKEN_REVOKED'));
    }

    // 3. Validate tenantId consistency
    if (req.tenantId && decoded.tenantId !== req.tenantId) {
      return next(AppError.forbidden('Token tenant mismatch'));
    }

    // 4. Load user — scope to tenantId to prevent cross-tenant access
    const user = await User.findOne({ _id: decoded.sub, tenantId: decoded.tenantId }).populate('role');
    if (!user) {
      return next(AppError.unauthorized('User not found'));
    }

    // 5. Account status checks
    if (user.isDeleted) return next(AppError.unauthorized('Account has been deleted'));
    if (!user.isActive || user.status === 'banned') {
      return next(AppError.unauthorized('Account is inactive or banned'));
    }
    if (user.status === 'suspended') {
      return next(AppError.forbidden('Account has been suspended'));
    }
    if (user.isLocked) {
      return next(AppError.locked('Account is temporarily locked'));
    }

    // 6. Attach to request
    req.user       = user;
    req.userId     = user._id;
    req.sessionId  = decoded.sessionId;
    req.deviceInfo = DeviceDetector.detectDevice(req);
    res.locals.user = user;

    next();
  } catch (err) {
    next(AppError.internal('Authentication error'));
  }
};

/**
 * Optional auth — populates req.user if a valid token is provided,
 * but does not reject the request if no token is present.
 */
const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return next();

  const token = authHeader.split(' ')[1];
  if (!token) return next();

  try {
    const decoded = verifyAccessToken(token);
    const user = await User.findOne({ _id: decoded.sub, tenantId: decoded.tenantId }).populate('role');
    if (user && user.isActive && !user.isDeleted) {
      req.user      = user;
      req.userId    = user._id;
      req.sessionId = decoded.sessionId;
    }
  } catch { /* ignore */ }

  next();
};

module.exports = { authMiddleware, optionalAuth };
