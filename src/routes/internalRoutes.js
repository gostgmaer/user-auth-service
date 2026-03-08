// src/routes/internalRoutes.js
// Service-to-service internal API — protected by a shared SERVICE_API_KEY,
// NOT by JWT.  Only sibling microservices (e.g. user-service) may call these
// endpoints to keep auth-service state in sync.
'use strict';

const express      = require('express');
const ctrl         = require('../controllers/adminAuthController');
const asyncHandler = require('../utils/asyncHandler');
const AppError     = require('../utils/appError');
const env          = require('../config/env');

const router = express.Router();

// ─── Service-key guard ────────────────────────────────────────────────────────
// Validates the shared x-api-key header sent by trusted sibling services.
function serviceKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!env.SERVICE_API_KEY || !key || key !== env.SERVICE_API_KEY) {
    return next(AppError.unauthorized('Invalid or missing service API key'));
  }
  next();
}

router.use(serviceKeyAuth);

// ─── Routes ───────────────────────────────────────────────────────────────────

// PATCH /api/internal/users/:userId/force-status
// Push a status/isActive/isDeleted change from user-service and optionally
// revoke all active tokens for that user.
router.patch('/users/:userId/force-status', asyncHandler(ctrl.forceStatusSync));

module.exports = router;
