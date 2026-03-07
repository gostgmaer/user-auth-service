// src/jobs/staleUserFieldCleaner.js
// Bulk clears expired transient fields on User documents:
//   - currentOTP               (expired OTP / MFA session data)
//   - emailVerificationToken   (unused verification link)
//   - passwordReset.token      (unused password-reset link)
//   - unlockToken              (unused account-unlock link)
//   - loginSecurity.lockedUntil (lock window has passed — auto-unlock)
//
// This supplements the pre-save hook which only runs when the document is saved.
// Documents that are never re-saved (e.g. abandoned accounts) are handled here.
'use strict';

const User   = require('../models/User');
const logger = require('../utils/logger');

const JOB_NAME = 'StaleUserFieldCleaner';

const run = async () => {
  const now = new Date();
  logger.info(`[${JOB_NAME}] Starting`);

  try {
    // ── 1. Clear expired OTPs ──────────────────────────────────────────────
    const otpResult = await User.updateMany(
      { 'currentOTP.expiresAt': { $lt: now } },
      { $unset: { currentOTP: '' } }
    );
    logger.info(`[${JOB_NAME}] Expired OTPs cleared`, { modified: otpResult.modifiedCount });

    // ── 2. Clear expired email-verification tokens ─────────────────────────
    const emailTokenResult = await User.updateMany(
      { emailVerificationTokenExpiry: { $lt: now }, emailVerificationToken: { $ne: null } },
      {
        $set: {
          emailVerificationToken:       null,
          emailVerificationTokenExpiry: null,
        },
      }
    );
    logger.info(`[${JOB_NAME}] Expired email verification tokens cleared`, {
      modified: emailTokenResult.modifiedCount,
    });

    // ── 3. Clear expired password-reset tokens ─────────────────────────────
    const pwResetResult = await User.updateMany(
      { 'passwordReset.tokenExpiry': { $lt: now }, 'passwordReset.token': { $ne: null } },
      {
        $set: {
          'passwordReset.token':       null,
          'passwordReset.tokenExpiry': null,
          'passwordReset.attempts':    0,
        },
      }
    );
    logger.info(`[${JOB_NAME}] Expired password-reset tokens cleared`, {
      modified: pwResetResult.modifiedCount,
    });

    // ── 4. Clear expired unlock tokens ────────────────────────────────────
    const unlockResult = await User.updateMany(
      { 'unlockToken.tokenExpiry': { $lt: now }, 'unlockToken.token': { $ne: null } },
      {
        $set: {
          'unlockToken.token':       null,
          'unlockToken.tokenExpiry': null,
        },
      }
    );
    logger.info(`[${JOB_NAME}] Expired unlock tokens cleared`, {
      modified: unlockResult.modifiedCount,
    });

    // ── 5. Auto-unlock accounts whose lock window has expired ─────────────
    const unlockAccounts = await User.updateMany(
      { 'loginSecurity.lockedUntil': { $lt: now } },
      {
        $set: {
          'loginSecurity.lockedUntil':    null,
          'loginSecurity.failedAttempts': 0,
        },
      }
    );
    logger.info(`[${JOB_NAME}] Expired account locks cleared`, {
      modified: unlockAccounts.modifiedCount,
    });

    logger.info(`[${JOB_NAME}] Completed successfully`);
  } catch (err) {
    logger.error(`[${JOB_NAME}] Failed`, { error: err.message, stack: err.stack });
  }
};

module.exports = { run };
