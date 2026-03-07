// src/services/activityLogService.js
const LogEntry = require('../models/LogEntry');
const DeviceDetector = require('./deviceDetector');
const logger = require('../utils/logger');

class ActivityLogService {
  /**
   * Log an auth event asynchronously (fire-and-forget safe).
   */
  async log(data) {
    try {
      await LogEntry.create({
        tenantId:   data.tenantId,
        userId:     data.userId   || null,
        role:       data.role     || 'user',
        sessionId:  data.sessionId || null,
        action:     data.action,
        operation:  data.operation || 'create',
        description: data.description || null,
        entity:     data.entity   || 'auth',
        entityId:   data.entityId || null,
        ipAddress:  data.ipAddress || null,
        userAgent:  data.userAgent || null,
        endpoint:   data.endpoint  || null,
        httpMethod: data.httpMethod || null,
        location:   data.location  || {},
        device:     data.device    || {},
        status:     data.status    || 'success',
        errorCode:  data.errorCode || null,
        errorMessage: data.errorMessage || null,
        metadata:   data.metadata  || {},
        sensitive:  data.sensitive || false,
      });
    } catch (err) {
      logger.warn('ActivityLogService: failed to write log entry', { error: err.message });
    }
  }

  /**
   * Build a log payload from an Express request.
   */
  fromRequest(req, overrides = {}) {
    const deviceInfo = DeviceDetector.detectDevice(req);
    const user = req.user;

    return {
      tenantId:   req.tenantId,
      userId:     user?._id || user?.id || null,
      role:       user?.role?.name || 'user',
      sessionId:  overrides.sessionId || null,
      ipAddress:  deviceInfo.ipAddress,
      userAgent:  deviceInfo.userAgent,
      endpoint:   req.originalUrl,
      httpMethod: req.method,
      location:   deviceInfo.location || {},
      device: {
        os:         deviceInfo.os?.name || null,
        browser:    deviceInfo.browser?.name || null,
        deviceType: deviceInfo.device?.type || 'unknown',
      },
      ...overrides,
    };
  }

  async logLogin(user, req, sessionId, method = 'password') {
    return this.log(this.fromRequest(req, {
      action:      'LOGIN',
      operation:   'create',
      description: `User ${user.email} logged in via ${method}`,
      entity:      'User',
      entityId:    user._id,
      sessionId,
      status:      'success',
      sensitive:   false,
      metadata:    { method, email: user.email },
    }));
  }

  async logLogout(user, req, sessionId) {
    return this.log(this.fromRequest(req, {
      action:      'LOGOUT',
      operation:   'delete',
      description: `User ${user.email} logged out`,
      entity:      'User',
      entityId:    user._id,
      sessionId,
      status:      'success',
    }));
  }

  async logRegistration(user, req) {
    return this.log(this.fromRequest(req, {
      action:      'REGISTER',
      operation:   'create',
      description: `New user registered: ${user.email}`,
      entity:      'User',
      entityId:    user._id,
      status:      'success',
    }));
  }

  async logFailedLogin(email, req, reason) {
    return this.log(this.fromRequest(req, {
      action:      'LOGIN_FAILED',
      operation:   'read',
      description: `Failed login attempt for: ${email} — ${reason}`,
      entity:      'User',
      status:      'failure',
      errorCode:   reason,
      metadata:    { email },
      sensitive:   true,
    }));
  }
}

module.exports = new ActivityLogService();
