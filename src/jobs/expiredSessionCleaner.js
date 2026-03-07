// src/jobs/expiredSessionCleaner.js
// Bulk removes expired and inactive session + refresh-token subdocuments from
// all User documents using MongoDB $pull. This supplements the on-save pre-hook
// by proactively cleaning documents that have not been saved recently.
'use strict';

const User   = require('../models/User');
const logger = require('../utils/logger');

const JOB_NAME = 'ExpiredSessionCleaner';

const run = async () => {
  const now = new Date();
  logger.info(`[${JOB_NAME}] Starting`);

  try {
    // ── 1. Pull expired / inactive activeSessions ──────────────────────────
    const sessionResult = await User.updateMany(
      { 'activeSessions.0': { $exists: true } },
      {
        $pull: {
          activeSessions: {
            $or: [
              { expiresAt: { $lt: now } },
              { isActive: false },
            ],
          },
        },
      }
    );

    logger.info(`[${JOB_NAME}] activeSessions cleaned`, {
      matchedUsers:   sessionResult.matchedCount,
      modifiedUsers:  sessionResult.modifiedCount,
    });

    // ── 2. Pull expired / inactive refreshTokens ───────────────────────────
    const tokenResult = await User.updateMany(
      { 'refreshTokens.0': { $exists: true } },
      {
        $pull: {
          refreshTokens: {
            $or: [
              { expiresAt: { $lt: now } },
              { isActive: false },
            ],
          },
        },
      }
    );

    logger.info(`[${JOB_NAME}] refreshTokens cleaned`, {
      matchedUsers:  tokenResult.matchedCount,
      modifiedUsers: tokenResult.modifiedCount,
    });

    logger.info(`[${JOB_NAME}] Completed successfully`);
  } catch (err) {
    logger.error(`[${JOB_NAME}] Failed`, { error: err.message, stack: err.stack });
  }
};

module.exports = { run };
