// src/middleware/errorHandler.js
const AppError = require('../utils/appError');
const logger   = require('../utils/logger');
const env      = require('../config/env');

const errorHandler = (err, req, res, next) => {
  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {}).join(', ');
    err = AppError.conflict(`Duplicate value for: ${field}`);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((e) => e.message);
    err = AppError.validation('Validation failed', messages);
  }

  // Mongoose cast error (invalid ObjectId)
  if (err.name === 'CastError') {
    err = AppError.badRequest(`Invalid ${err.path}: ${err.value}`);
  }

  // JWT errors that might slip through
  if (err.name === 'JsonWebTokenError')  err = AppError.unauthorized('Invalid token');
  if (err.name === 'TokenExpiredError')  err = AppError.unauthorized('Token has expired', 'TOKEN_EXPIRED');
  if (err.name === 'NotBeforeError')     err = AppError.unauthorized('Token not yet valid');

  // Default to 500 for non-operational errors
  const statusCode    = err.statusCode || 500;
  const isOperational = err.isOperational ?? false;
  const isProd        = env.IS_PROD;

  // Log server errors
  if (statusCode >= 500) {
    logger.error('Server error', {
      statusCode,
      message: err.message,
      stack:   err.stack,
      url:     req.originalUrl,
      method:  req.method,
      tenantId: req.tenantId,
      userId:   req.user?._id?.toString(),
    });
  }

  const response = {
    success: false,
    statusCode,
    message: isOperational || !isProd ? err.message : 'An unexpected error occurred',
    error: {
      code: err.code || 'INTERNAL_ERROR',
    },
  };

  if (err.validationErrors) response.error.errors = err.validationErrors;
  if (err.details && !isProd) response.error.details = err.details;
  if (!isProd && !isOperational) response.error.stack = err.stack;

  res.status(statusCode).json(response);
};

module.exports = { errorHandler };
