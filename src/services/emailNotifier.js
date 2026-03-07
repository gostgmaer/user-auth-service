// src/services/emailNotifier.js
const axios  = require('axios');
const logger = require('../utils/logger');
const env    = require('../config/env');

const EMAIL_SERVICE_URL = env.EMAIL_SERVICE_URL;

/**
 * Send an email via the external email microservice.
 * ALWAYS fire-and-forget. Callers must NOT await this.
 * Failures are logged but never surfaced to the user.
 */
const send = (payload) => {
  // Intentionally not awaited
  axios
    .post(`${EMAIL_SERVICE_URL}/send-email`, payload, { timeout: 5000 })
    .catch((err) =>
      logger.warn('Email notification failed (non-fatal)', {
        template: payload?.templateKey,
        to:       payload?.to,
        error:    err.message,
      })
    );
};

module.exports = { send };
