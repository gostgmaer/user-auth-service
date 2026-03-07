// src/validators/auth.js
const { check, body, validationResult } = require('express-validator');
const AppError = require('../utils/appError');

const PASSWORD_RULES = body('password')
  .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
  .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
  .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
  .matches(/\d/).withMessage('Password must contain at least one digit')
  .matches(/[@$!%*?&^#()_\-+=~`|\\[\]{};:'",<.>/?]/).withMessage('Password must contain at least one special character');

const validateRegister = [
  check('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  check('username').optional().isLength({ min: 3, max: 30 }).trim().withMessage('Username must be 3–30 characters'),
  check('firstName').optional().trim().notEmpty().withMessage('First name cannot be blank'),
  check('lastName').optional().trim().notEmpty().withMessage('Last name cannot be blank'),
  PASSWORD_RULES,
  check('confirmPassword')
    .custom((val, { req }) => val === req.body.password)
    .withMessage('Passwords do not match'),
];

const validateLogin = [
  check('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  check('password').notEmpty().withMessage('Password is required'),
];

const validateForgotPassword = [
  check('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
];

const validateResetPassword = [
  check('token').notEmpty().withMessage('Reset token is required'),
  PASSWORD_RULES,
];

const validateChangePassword = [
  check('currentPassword').notEmpty().withMessage('Current password is required'),
  body('password')
    .isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('New password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('New password must contain at least one lowercase letter')
    .matches(/\d/).withMessage('New password must contain at least one digit')
    .matches(/[@$!%*?&^#()_\-+=~`|\\[\]{};:'",<.>/?]/).withMessage('New password must contain at least one special character'),
];

const validateVerifyEmail = [
  check('token').notEmpty().withMessage('Verification token is required'),
];

const validateUpdateProfile = [
  check('firstName').optional().trim().notEmpty().withMessage('First name cannot be blank')
    .isLength({ max: 50 }).withMessage('First name must be 50 characters or fewer'),
  check('lastName').optional().trim().notEmpty().withMessage('Last name cannot be blank')
    .isLength({ max: 50 }).withMessage('Last name must be 50 characters or fewer'),
  check('username').optional().trim()
    .isLength({ min: 3, max: 30 }).withMessage('Username must be 3–30 characters')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username may only contain letters, digits, and underscores'),
  check('phoneNumber').optional().isMobilePhone().withMessage('Invalid phone number'),
  check('dateOfBirth').optional().isISO8601().toDate().withMessage('dateOfBirth must be a valid ISO 8601 date'),
  check('gender').optional()
    .isIn(['male', 'female', 'other', 'prefer_not_to_say']).withMessage('Invalid gender value'),
  check('profilePicture').optional().isObject().withMessage('profilePicture must be an object'),
  check('profilePicture.url').optional().isURL().withMessage('profilePicture.url must be a valid URL'),
  check('profilePicture.name').optional().trim().isLength({ max: 100 }).withMessage('profilePicture.name max 100 characters'),
];

/**
 * Middleware to check for express-validator errors and return 400.
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages = errors.array().map((e) => e.msg);
    return next(AppError.validation('Validation failed', errors.array()));
  }
  next();
};

module.exports = {
  validateRegister,
  validateLogin,
  validateForgotPassword,
  validateResetPassword,
  validateChangePassword,
  validateVerifyEmail,
  validateUpdateProfile,
  validate,
};
