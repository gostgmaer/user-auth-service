// src/jobs/securityEventsTrimmer.js
// Caps User.securityEvents[] to MAX_SECURITY_EVENTS (env, default 200).
// Uses a pipeline-based updateMany with $slice so every user document is
// processed in one MongoDB round-trip per batch.
//
// Runs weekly — the pre-save hook and logSecurityEvent() method already trim
// in the hot path; this handles users who haven't triggered a save recently.
'use strict';

const User   = require('../models/User');
const logger = require('../utils/logger');

const JOB_NAME = 'SecurityEventsTrimmer';

const run = async () => {
  const cap = parseInt(process.env.MAX_SECURITY_EVENTS || '200', 10);
  logger.info(`[${JOB_NAME}] Starting — cap = ${cap}`);

  try {
    // Only process documents that actually exceed the cap
    const result = await User.updateMany(
      { [`securityEvents.${cap}`]: { $exists: true } },
      [
        {
          $set: {
            securityEvents: {
              $slice: ['$securityEvents', -cap],
            },
          },
        },
      ]
    );

    logger.info(`[${JOB_NAME}] Completed`, {
      matched:  result.matchedCount,
      modified: result.modifiedCount,
    });
  } catch (err) {
    logger.error(`[${JOB_NAME}] Failed`, { error: err.message, stack: err.stack });
  }
};

module.exports = { run };
