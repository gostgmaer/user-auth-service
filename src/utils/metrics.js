// src/utils/metrics.js — Prometheus instrumentation
// Exposes standard HTTP + auth-specific metrics via prom-client.
// The /health/metrics route serves the text output.
'use strict';

const client = require('prom-client');

// ─── Default Node.js metrics (GC, event loop lag, memory, fd count …) ────────
const register = new client.Registry();
client.collectDefaultMetrics({ register, prefix: 'uas_node_' });

// ─── HTTP request duration histogram ─────────────────────────────────────────
const httpRequestDuration = new client.Histogram({
  name: 'uas_http_request_duration_seconds',
  help: 'HTTP request latency in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [register],
});

// ─── HTTP total counter ───────────────────────────────────────────────────────
const httpRequestTotal = new client.Counter({
  name: 'uas_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

// ─── Auth event counters ──────────────────────────────────────────────────────
const authEvents = new client.Counter({
  name: 'uas_auth_events_total',
  help: 'Auth lifecycle events',
  labelNames: ['event', 'tenant'],  // event: login_success / login_fail / register / logout / token_refresh / mfa_challenge
  registers: [register],
});

// ─── Active sessions gauge ────────────────────────────────────────────────────
const activeSessions = new client.Gauge({
  name: 'uas_active_sessions',
  help: 'Estimated number of active user sessions',
  labelNames: ['tenant'],
  registers: [register],
});

// ─── Token revocation counter ─────────────────────────────────────────────────
const tokenRevocations = new client.Counter({
  name: 'uas_token_revocations_total',
  help: 'Number of tokens revoked (logout / forced / suspicious)',
  labelNames: ['reason', 'store'],
  registers: [register],
});

// ─── Email notification counter ───────────────────────────────────────────────
const emailNotifications = new client.Counter({
  name: 'uas_email_notifications_total',
  help: 'Outgoing email notifications',
  labelNames: ['template', 'status'],  // status: sent / failed / circuit_open
  registers: [register],
});

// ─── Rate limit hits counter ──────────────────────────────────────────────────
const rateLimitHits = new client.Counter({
  name: 'uas_rate_limit_hits_total',
  help: 'Number of requests blocked by rate limiter',
  labelNames: ['limiter'],
  registers: [register],
});

// ─── Express middleware that records per-route metrics ───────────────────────
const metricsMiddleware = (req, res, next) => {
  // Normalise route patterns to avoid label cardinality explosion
  // e.g.  /api/auth/users/60d2b4/sessions → /api/auth/users/:id/sessions
  const end = httpRequestDuration.startTimer();

  res.on('finish', () => {
    const route  = req.route?.path
      ? `${req.baseUrl || ''}${req.route.path}`
      : req.path.replace(/\/[0-9a-fA-F]{24}/g, '/:id').replace(/\/[0-9]+/g, '/:num');
    const labels = { method: req.method, route, status_code: res.statusCode };
    end(labels);
    httpRequestTotal.inc(labels);
  });

  next();
};

/**
 * Convenience helpers called from controllers/services.
 */
const recordAuthEvent  = (event, tenant = 'unknown') => authEvents.inc({ event, tenant });
const recordRevocation = (reason, store)             => tokenRevocations.inc({ reason, store });
const recordEmail      = (template, status)          => emailNotifications.inc({ template, status });
const recordRateLimit  = (limiter)                   => rateLimitHits.inc({ limiter });
const setActiveSessions = (tenant, count)            => activeSessions.set({ tenant }, count);

module.exports = {
  register,
  metricsMiddleware,
  recordAuthEvent,
  recordRevocation,
  recordEmail,
  recordRateLimit,
  setActiveSessions,
};
