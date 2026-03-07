// src/services/emailNotifier.js
'use strict';

const axios  = require('axios');
const logger = require('../utils/logger');
const env    = require('../config/env');
const { recordEmail } = require('../utils/metrics');

const EMAIL_SERVICE_URL = env.EMAIL_SERVICE_URL;

// ─── Circuit breaker state ────────────────────────────────────────────────────
// States: CLOSED (normal) → OPEN (failing fast) → HALF_OPEN (probing)
const CB = {
  state:       'CLOSED',
  failures:    0,
  threshold:   5,          // consecutive failures before opening
  cooldownMs:  30_000,     // 30 s before trying again (half-open probe)
  nextRetryAt: 0,
};

const _onSuccess = (template) => {
  CB.failures = 0;
  if (CB.state !== 'CLOSED') {
    CB.state = 'CLOSED';
    logger.info('EmailNotifier: circuit CLOSED — email service recovered');
  }
  recordEmail(template, 'sent');
};

const _onFailure = (template, errMsg) => {
  CB.failures++;
  recordEmail(template, 'failed');
  logger.warn('EmailNotifier: delivery failure', { template, error: errMsg, failures: CB.failures });

  if (CB.failures >= CB.threshold) {
    CB.state       = 'OPEN';
    CB.nextRetryAt = Date.now() + CB.cooldownMs;
    logger.error('EmailNotifier: circuit OPENED — email service unavailable', {
      cooldownMs: CB.cooldownMs,
      retryAt:    new Date(CB.nextRetryAt).toISOString(),
    });
  }
};

/**
 * Send an email via the external email microservice.
 * ALWAYS fire-and-forget. Callers must NOT await this.
 * Failures are logged but never surfaced to the user.
 */
const send = (payload) => {
  // Fast-fail if circuit is open and cooldown has not elapsed
  if (CB.state === 'OPEN') {
    if (Date.now() < CB.nextRetryAt) {
      recordEmail(payload?.templateKey || 'unknown', 'circuit_open');
      logger.debug('EmailNotifier: circuit OPEN — suppressing email', { template: payload?.templateKey });
      return;
    }
    // Cooldown elapsed — probe with one request (half-open)
    CB.state = 'HALF_OPEN';
    logger.info('EmailNotifier: circuit HALF_OPEN — probing email service');
  }

  const template = payload?.templateKey || 'unknown';

  // Intentionally not awaited
  axios
    .post(`${EMAIL_SERVICE_URL}/send-email`, payload, { timeout: 5000 })
    .then(() => _onSuccess(template))
    .catch((err) => _onFailure(template, err.message));
};

/**
 * Expose circuit-breaker status for the /health/ready probe.
 */
const getCircuitStatus = () => ({ ...CB });

module.exports = { send, getCircuitStatus };
