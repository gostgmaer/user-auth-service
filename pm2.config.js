// pm2.config.js — PM2 ecosystem for production
// Usage:
//   npm run start:cluster       → pm2 start pm2.config.js --env production
//   pm2 logs user-auth-service  → tail logs
//   pm2 monit                   → live dashboard
'use strict';

module.exports = {
  apps: [
    {
      name: 'user-auth-service',
      script: 'server.js',

      // ─── Clustering ────────────────────────────────────────────────────────
      instances: process.env.WEB_CONCURRENCY || 'max', // 'max' = 1 per logical CPU
      exec_mode: 'cluster',

      // ─── Runtime ───────────────────────────────────────────────────────────
      node_args: '--max-old-space-size=460',            // soft cap under 512 MiB container
      max_memory_restart: '480M',                        // auto-restart if RSS exceeds limit

      // ─── Restart behaviour ─────────────────────────────────────────────────
      autorestart: true,
      exp_backoff_restart_delay: 100,   // starts at 100 ms, doubles up to 15 s
      max_restarts: 10,
      min_uptime: '5s',

      // ─── Graceful shutdown ─────────────────────────────────────────────────
      kill_timeout: 12000,              // 12 s — must exceed server.js forceExit (10 s)
      listen_timeout: 5000,
      shutdown_with_message: false,
      wait_ready: false,

      // ─── Logging ───────────────────────────────────────────────────────────
      // Winston writes structured JSON to stdout/stderr; PM2 captures them.
      // console output is already in JSON — disable PM2's own timestamp wrapper.
      log_date_format: '',
      combine_logs: true,
      out_file: 'logs/pm2-out.log',
      error_file: 'logs/pm2-error.log',
      merge_logs: true,

      // ─── Environment ───────────────────────────────────────────────────────
      env: {
        NODE_ENV: 'development',
      },
      env_production: {
        NODE_ENV: 'production',
        CLEANUP_ENABLED: 'true',
      },
      env_staging: {
        NODE_ENV: 'production',
        LOG_LEVEL: 'debug',
        CLEANUP_ENABLED: 'true',
      },
    },
  ],
};
