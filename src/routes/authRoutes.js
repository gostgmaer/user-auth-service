// src/routes/authRoutes.js
'use strict';

const express  = require('express');
const ctrl     = require('../controllers/authController');
const asyncHandler = require('../utils/asyncHandler');
const { authMiddleware, optionalAuth } = require('../middleware/auth');
const { loginLimiter, registerLimiter, otpLimiter, resetLimiter, verifyLimiter, refreshLimiter } = require('../middleware/rateLimit');
const {
  validateRegister,
  validateLogin,
  validateForgotPassword,
  validateResetPassword,
  validateChangePassword,
  validateVerifyEmail,
  validateUpdateProfile,
  validate,
} = require('../validators/auth');

const router = express.Router();

// ─── Public Routes ────────────────────────────────────────────────────────────

// Registration
router.post('/register',
  registerLimiter,
  validateRegister,
  validate,
  asyncHandler(ctrl.register)
);

// Login
router.post('/login',
  loginLimiter,
  validateLogin,
  validate,
  asyncHandler(ctrl.login)
);

// MFA login completion
router.post('/login/mfa',
  loginLimiter,
  asyncHandler(ctrl.verifyMfaLogin)
);

// Token operations
router.post("/token/refresh", refreshLimiter, asyncHandler(ctrl.refreshToken));
router.post('/token/verify',   verifyLimiter, asyncHandler(ctrl.verifyToken));

// Email verification
router.post('/email/verify',
  validateVerifyEmail,
  validate,
  asyncHandler(ctrl.verifyEmail)
);
router.post('/email/resend',
  otpLimiter,
  asyncHandler(ctrl.resendVerification)
);

// Password
router.post('/password/forgot',
  resetLimiter,
  validateForgotPassword,
  validate,
  asyncHandler(ctrl.forgotPassword)
);
router.post('/password/reset',
  resetLimiter,
  validateResetPassword,
  validate,
  asyncHandler(ctrl.resetPassword)
);

// OTP
router.post('/otp/verify',  otpLimiter, asyncHandler(ctrl.verifyOtp));
router.post('/otp/resend',  otpLimiter, asyncHandler(ctrl.resendOtp));

// Logout is public — token and cookies may not exist
router.post('/logout', asyncHandler(ctrl.logout));

// Account unlock (self-service, email-token based)
router.post('/account/unlock/request', resetLimiter, asyncHandler(ctrl.requestAccountUnlock));
router.post('/account/unlock/confirm', asyncHandler(ctrl.confirmAccountUnlock));

// ─── Protected Routes ─────────────────────────────────────────────────────────

router.use(authMiddleware);

// Password change (requires current password)
router.post('/password/change',
  validateChangePassword,
  validate,
  asyncHandler(ctrl.changePassword)
);

// Profile — /me per API contract
router.get('/me',    asyncHandler(ctrl.getProfile));
router.patch('/me',  validateUpdateProfile, validate, asyncHandler(ctrl.updateProfile));

// Sessions
router.get('/sessions',                asyncHandler(ctrl.getSessions));
router.delete('/sessions/:sessionId',  asyncHandler(ctrl.revokeSession));
router.delete('/sessions',             asyncHandler(ctrl.revokeAllSessions));

// Devices
router.get('/devices',                 asyncHandler(ctrl.getDevices));
router.patch('/devices/:deviceId/trust', asyncHandler(ctrl.toggleDeviceTrust));
router.delete('/devices/:deviceId',    asyncHandler(ctrl.removeDevice));

// MFA / TOTP — /mfa/totp/* per API contract
router.post('/mfa/totp/setup',                  asyncHandler(ctrl.setupTotp));
router.post('/mfa/totp/verify',                 asyncHandler(ctrl.verifyTotpSetup));
router.delete('/mfa/totp',                      asyncHandler(ctrl.disableTotp));
router.get('/mfa/backup-codes',                 asyncHandler(ctrl.getBackupCodes));
router.post('/mfa/backup-codes/regenerate',     asyncHandler(ctrl.regenerateBackupCodes));

// OTP settings
router.patch('/otp/settings',          asyncHandler(ctrl.updateOtpSettings));

// Phone
router.post('/phone/verify',           asyncHandler(ctrl.verifyPhone));
router.post('/phone/resend',           otpLimiter, asyncHandler(ctrl.resendPhoneOtp));

// GDPR / Account self-service — /me per API contract
router.delete('/me',           asyncHandler(ctrl.deleteOwnAccount));
router.get('/me/export',       asyncHandler(ctrl.exportAccountData));
router.get('/me/security-events', asyncHandler(ctrl.getSecurityEvents));

module.exports = router;
