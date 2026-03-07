// src/middleware/otpMiddleware.js
const otpService = require('../services/otpService');
const User       = require('../models/User');
const AppError   = require('../utils/appError');
const env        = require('../config/env');

/**
 * Require OTP verification for sensitive operations.
 * @param {string} operationType - 'login' | 'sensitive_op' | etc.
 */
const requireOTPVerification = (operationType = 'sensitive_op') => {
  return async (req, res, next) => {
    try {
      // Skip if OTP is globally disabled
      if (!env.ENABLE_OTP_VERIFICATION) return next();

      if (!req.user) return next(AppError.unauthorized('Authentication required'));

      const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
      if (!user) return next(AppError.notFound('User not found'));

      // Skip if user has not enabled OTP
      if (!user.otpSettings?.enabled) return next();

      // Check if already verified in this request (via req.otpVerified set by verifyOtp controller)
      if (req.otpVerified === true) return next();

      return next(
        new (require('../utils/appError'))(403, 'OTP verification required for this operation', 'OTP_REQUIRED', {
          operationType,
          methods: otpService.getAvailableMethods(user),
          verifyEndpoint: '/api/auth/otp/verify',
        })
      );
    } catch (err) {
      return next(AppError.internal('OTP middleware error'));
    }
  };
};

module.exports = { requireOTPVerification };
