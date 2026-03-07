// src/jobs/cleanupManager.js
// Central cleanup scheduler using plain Node.js setInterval (no external deps).
// Call startAll() once, after the database connection is established.
//
// Set CLEANUP_ENABLED=false in env to disable all jobs (useful in test /
// migration environments where you don't want background activity).
//
// Intervals:
//   StaleUserFieldCleaner   — every 30 minutes
//   ExpiredSessionCleaner   — every 6 hours
//   SecurityEventsTrimmer   — every 7 days
'use strict';

const logger = require('../utils/logger');

const expiredSessionCleaner = require('./expiredSessionCleaner');
const staleUserFieldCleaner = require('./staleUserFieldCleaner');
const securityEventsTrimmer = require('./securityEventsTrimmer');

const ENABLED = process.env.CLEANUP_ENABLED !== 'false';

const MINUTE = 60 * 1000;
const HOUR   = 60 * MINUTE;
const DAY    = 24 * HOUR;

// Registry: { name, intervalMs, job }
const JOBS = [
  {
    name:       'StaleUserFieldCleaner',
    intervalMs: 30 * MINUTE,   // every 30 minutes
    job:        staleUserFieldCleaner,
  },
  {
    name:       'ExpiredSessionCleaner',
    intervalMs: 6 * HOUR,      // every 6 hours
    job:        expiredSessionCleaner,
  },
  {
    name:       'SecurityEventsTrimmer',
    intervalMs: 7 * DAY,       // every 7 days
    job:        securityEventsTrimmer,
  },
];

// Keep timer references so the process can be cleanly shut down.
const timers = [];

const runSafe = async (name, job) => {
  try {
    await job.run();
  } catch (err) {
    // Individual jobs already catch their own errors, but we guard here so
    // one failing job can never crash the Node process.
    logger.error(`[CleanupManager] Unhandled error in ${name}`, {
      error: err.message,
      stack: err.stack,
    });
  }
};

const startAll = () => {
  if (!ENABLED) {
    logger.info('[CleanupManager] CLEANUP_ENABLED=false — all jobs skipped');
    return;
  }

  for (const { name, intervalMs, job } of JOBS) {
    // Run immediately on startup so we don't wait a full interval on first boot
    runSafe(name, job);

    const timer = setInterval(() => runSafe(name, job), intervalMs);
    // unref() lets Node exit naturally even if these timers are still pending
    timer.unref();
    timers.push(timer);

    logger.info(`[CleanupManager] Registered ${name} — interval: ${intervalMs / MINUTE} min`);
  }

  logger.info('[CleanupManager] All cleanup jobs registered');
};

const stopAll = () => {
  for (const timer of timers) clearInterval(timer);
  timers.length = 0;
  logger.info('[CleanupManager] All cleanup jobs stopped');
};

module.exports = { startAll, stopAll };
