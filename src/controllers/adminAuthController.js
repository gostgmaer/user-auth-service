// src/controllers/adminAuthController.js
//
// Auth-intrinsic admin operations ONLY.
// User-management operations (list, suspend, reinstate, delete, meta)
// belong in a dedicated user-management-service.
'use strict';

const User      = require('../models/User');
const LogEntry  = require('../models/LogEntry');
const activityLog             = require('../services/activityLogService');
const { revokeAllUserTokens } = require('../services/tokenRevocationService');
const emailNotifier   = require('../services/emailNotifier');
const emailPayloads   = require('../email/emailPayloads');
const AppError  = require('../utils/appError');
const { sendSuccess, sendPaginated } = require('../utils/responseHelper');
const { stripId } = require('../utils/helper');

// ─── Account Unlock ────────────────────────────────────────────────────────────

// POST /api/admin/users/:userId/unlock — clear lockout set by failed-login throttle
// Auth-intrinsic: modifies loginAttempts / isLocked fields owned by this service.
exports.unlockAccount = async (req, res, next) => {
  const { userId } = req.params;
  const tenantId   = req.tenantId;

  const user = await User.findOne({ _id: userId, tenantId, isDeleted: { $ne: true } });
  if (!user) return next(AppError.notFound('User not found'));

  user.updatedBy = req.user._id;
  await user.resetFailedLogin(); // clears loginAttempts, isLocked, lockUntil
  activityLog.log({ action: 'ACCOUNT_UNLOCKED', userId: user._id, tenantId, performedBy: req.user._id });
  emailNotifier.send(emailPayloads.accountUnlockConfirmed(user));
  return sendSuccess(res, 'Account unlocked');
};

// ─── Sessions ─────────────────────────────────────────────────────────────────

// GET /api/admin/sessions  — list all active sessions across the tenant (optional ?userId filter)
exports.listActiveSessions = async (req, res, next) => {
  const tenantId = req.tenantId;
  const filter = { tenantId, isDeleted: { $ne: true }, 'activeSessions.isActive': true };
  if (req.query.userId) filter._id = req.query.userId;

  const users = await User.find(filter).select('_id email username activeSessions');
  const sessions = [];
  for (const user of users) {
    (user.activeSessions || []).filter((s) => s.isActive).forEach((s) => {
      sessions.push({
        ...stripId(s),
        userId:   user._id,
        email:    user.email,
        username: user.username,
      });
    });
  }
  return sendSuccess(res, 'Active sessions', sessions);
};

// DELETE /api/admin/sessions/:sessionId — find owner and revoke
exports.forceRevokeSession = async (req, res, next) => {
  const { sessionId } = req.params;
  const tenantId      = req.tenantId;

  const user = await User.findOne({ tenantId, 'activeSessions.sessionId': sessionId });
  if (!user) return next(AppError.notFound('Session not found'));
  const session = user.activeSessions.find((s) => s.sessionId === sessionId && s.isActive);
  if (!session) return next(AppError.notFound('Session already revoked'));
  session.isActive = false;
  await user.save();
  activityLog.log({ action: 'SESSION_FORCE_REVOKED', userId: user._id, tenantId, performedBy: req.user._id, meta: { sessionId } });
  return sendSuccess(res, 'Session revoked');
};

// ─── Logs & Analytics ─────────────────────────────────────────────────────────

exports.getActivityLogs = async (req, res, next) => {
  const tenantId = req.tenantId;
  const page     = Math.max(1, parseInt(req.query.page  || '1', 10));
  const limit    = Math.min(200, parseInt(req.query.limit || '50', 10));
  const skip     = (page - 1) * limit;

  const filter = { tenantId };
  if (req.query.userId) filter.userId = req.query.userId;
  if (req.query.action) filter.action = req.query.action;
  if (req.query.from || req.query.to) {
    filter.createdAt = {};
    if (req.query.from) filter.createdAt.$gte = new Date(req.query.from);
    if (req.query.to)   filter.createdAt.$lte = new Date(req.query.to);
  }

  const [logs, total] = await Promise.all([
    LogEntry.find(filter).skip(skip).limit(limit).sort({ createdAt: -1 }),
    LogEntry.countDocuments(filter),
  ]);

  return sendPaginated(res, 'Activity logs', logs, total, page, limit);
};

exports.getAuthAnalytics = async (req, res, next) => {
  const tenantId = req.tenantId;
  const days     = parseInt(req.query.days || '30', 10);
  const since    = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const [
    totalUsers,
    activeUsers,
    pendingUsers,
    suspendedUsers,
    totalLogins,
    failedLogins,
    registrations,
  ] = await Promise.all([
    User.countDocuments({ tenantId, isDeleted: { $ne: true } }),
    User.countDocuments({ tenantId, status: 'active', isDeleted: { $ne: true } }),
    User.countDocuments({ tenantId, status: 'pending' }),
    User.countDocuments({ tenantId, status: 'suspended' }),
    LogEntry.countDocuments({ tenantId, action: 'LOGIN', createdAt: { $gte: since } }),
    LogEntry.countDocuments({ tenantId, action: 'LOGIN_FAILED', createdAt: { $gte: since } }),
    LogEntry.countDocuments({ tenantId, action: 'USER_REGISTERED', createdAt: { $gte: since } }),
  ]);

  // Daily breakdown for the last 7 days
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const dailyActivity = await LogEntry.aggregate([
    { $match: { tenantId, createdAt: { $gte: sevenDaysAgo }, action: { $in: ['LOGIN', 'USER_REGISTERED'] } } },
    { $group: {
      _id: {
        date:   { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
        action: '$action',
      },
      count: { $sum: 1 },
    } },
    { $sort: { '_id.date': 1 } },
  ]);

  return sendSuccess(res, 'Auth analytics', {
    users:    { total: totalUsers, active: activeUsers, pending: pendingUsers, suspended: suspendedUsers },
    period:   { days, since },
    activity: { totalLogins, failedLogins, registrations },
    daily:    dailyActivity,
  });
};

// ─── Internal Service Endpoint ────────────────────────────────────────────────

// PATCH /api/internal/users/:userId/force-status
// Called by sibling microservices to sync user state + revoke active tokens.
// Protected by SERVICE_API_KEY (x-api-key header) — not by JWT.
exports.forceStatusSync = async (req, res, next) => {
  const { userId }                                        = req.params;
  const tenantId                                         = req.tenantId;
  const { isActive, status, isDeleted, invalidateSessions } = req.body;

  const user = await User.findOne({ _id: userId, tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  if (isActive  !== undefined) user.isActive  = isActive;
  if (status    !== undefined) user.status    = status;
  if (isDeleted !== undefined) user.isDeleted = isDeleted;
  await user.save();

  const shouldRevoke =
    isActive === false ||
    isDeleted === true ||
    invalidateSessions === true ||
    ['banned', 'deleted', 'suspended', 'inactive'].includes(status);

  if (shouldRevoke) await revokeAllUserTokens(user, 'admin_force_status');

  return sendSuccess(res, 'User status synced');
};
