// src/utils/appError.js

const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  LOCKED: 423,
  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,
};

const ERROR_CODES = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  REFRESH_TOKEN_REUSED: 'REFRESH_TOKEN_REUSED',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  BAD_REQUEST: 'BAD_REQUEST',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  MFA_REQUIRED: 'MFA_REQUIRED',
  OTP_REQUIRED: 'OTP_REQUIRED',
};

class AppError extends Error {
  constructor(statusCode, message, code = null, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code || (statusCode >= 500 ? ERROR_CODES.INTERNAL_ERROR : ERROR_CODES.BAD_REQUEST);
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(message = 'Bad request', details = null) {
    return new AppError(HTTP_STATUS.BAD_REQUEST, message, ERROR_CODES.BAD_REQUEST, details);
  }

  static unauthorized(message = 'Authentication required', code = ERROR_CODES.UNAUTHORIZED) {
    return new AppError(HTTP_STATUS.UNAUTHORIZED, message, code);
  }

  static forbidden(message = 'Access denied') {
    return new AppError(HTTP_STATUS.FORBIDDEN, message, ERROR_CODES.FORBIDDEN);
  }

  static notFound(message = 'Resource not found') {
    return new AppError(HTTP_STATUS.NOT_FOUND, message, ERROR_CODES.NOT_FOUND);
  }

  static conflict(message = 'Resource already exists') {
    return new AppError(HTTP_STATUS.CONFLICT, message, ERROR_CODES.DUPLICATE_ENTRY);
  }

  static validation(message = 'Validation failed', errors = null) {
    const err = new AppError(HTTP_STATUS.BAD_REQUEST, message, ERROR_CODES.VALIDATION_ERROR);
    err.validationErrors = errors;
    return err;
  }

  static tooManyRequests(message = 'Too many requests, please try again later') {
    return new AppError(HTTP_STATUS.TOO_MANY_REQUESTS, message, ERROR_CODES.RATE_LIMIT_EXCEEDED);
  }

  static locked(message = 'Account is locked') {
    return new AppError(HTTP_STATUS.LOCKED, message, ERROR_CODES.ACCOUNT_LOCKED);
  }

  static internal(message = 'Internal server error') {
    return new AppError(HTTP_STATUS.INTERNAL_SERVER_ERROR, message, ERROR_CODES.INTERNAL_ERROR);
  }
}

module.exports = AppError;
module.exports.HTTP_STATUS = HTTP_STATUS;
module.exports.ERROR_CODES = ERROR_CODES;
