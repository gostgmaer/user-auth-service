// src/routes/adminRoutes.js
'use strict';

const express = require('express');
const ctrl    = require('../controllers/adminAuthController');
const asyncHandler  = require('../utils/asyncHandler');
const { authMiddleware } = require('../middleware/auth');
const roleCheck          = require('../middleware/roleCheck');

const router = express.Router();

// All admin routes require authentication + admin/super_admin role
router.use(authMiddleware);
router.use(roleCheck('admin', 'super_admin'));

// ── Account unlock (auth-intrinsic: clears loginAttempts / isLocked) ──────────
router.post('/users/:userId/unlock',     asyncHandler(ctrl.unlockAccount));

// ── Sessions (auth-intrinsic: reads/revokes tokens owned by this service) ──────
router.get('/sessions',                  asyncHandler(ctrl.listActiveSessions));
router.delete('/sessions/:sessionId',    asyncHandler(ctrl.forceRevokeSession));

// ── Logs & Analytics (auth-intrinsic: reads LogEntry data owned by this service)
router.get('/logs',                      asyncHandler(ctrl.getActivityLogs));
router.get('/analytics',                 asyncHandler(ctrl.getAuthAnalytics));

// NOTE: User CRUD (list, get, suspend, reinstate, delete, meta) lives in the
// separate user-management-service, not here.

module.exports = router;
