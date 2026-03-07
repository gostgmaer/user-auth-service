// src/middleware/requestTimeout.js
// Hard per-request timeout to prevent slow DB queries / runaway handlers
// from holding open connections indefinitely.
'use strict';

const AppError = require('../utils/appError');

/**
 * @param {number} ms  Timeout in milliseconds (default: 30 000)
 */
const requestTimeout = (ms = 30_000) => (req, res, next) => {
  const timer = setTimeout(() => {
    if (res.headersSent) return;
    next(AppError.badRequest('Request timed out'));
  }, ms);

  // Clear the timer as soon as the response is sent so it doesn't hold the event loop
  res.on('finish', () => clearTimeout(timer));
  res.on('close',  () => clearTimeout(timer));

  next();
};

module.exports = requestTimeout;
