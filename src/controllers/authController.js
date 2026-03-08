// src/controllers/authController.js
'use strict';

const { v4: uuidv4 }  = require('uuid');
const crypto          = require('crypto');
const User            = require('../models/User');
const Role            = require('../models/Role');
const { generateTokens, verifyRefreshToken, setCookiesOnHeader, clearAuthCookies, expiryToSeconds }
                      = require('../services/tokenService');
const { revokeToken, isTokenRevoked, revokeAllUserTokens }
                      = require('../services/tokenRevocationService');
const otpService      = require('../services/otpService');
const activityLog     = require('../services/activityLogService');
const DeviceDetector  = require('../services/deviceDetector');
const emailNotifier   = require('../services/emailNotifier');
const emailPayloads   = require('../email/emailPayloads');
const AppError        = require('../utils/appError');
const { sendSuccess, sendCreated, sendError } = require('../utils/responseHelper');
const { sanitizeUser, stripId } = require('../utils/helper');
const { hashPassword, verifyPassword, hashToken, generateSecureToken, checkPasswordStrength }
                      = require('../utils/security');
const { verifyAccessToken } = require('../services/tokenService');
const jwtConfig       = require('../config/jwt');
const env             = require('../config/env');
const logger = require('../utils/logger');

const EMAIL_VERIFY_EXPIRY_HOURS   = env.EMAIL_VERIFY_EXPIRY_HOURS;
const PASSWORD_RESET_EXPIRY_HOURS = env.PASSWORD_RESET_EXPIRY_HOURS;
const MAX_LOGIN_ATTEMPTS          = env.MAX_LOGIN_ATTEMPTS;

// ─── Helpers ────────────────────────────────────────────────────────────────

const buildSession = (deviceInfo) => ({
  sessionId: uuidv4(),
  deviceId:  deviceInfo.deviceId || uuidv4(),
  deviceInfo: {
    browser:   deviceInfo.browser?.name,
    os:        deviceInfo.os?.name,
    type:      deviceInfo.device?.type || 'desktop',
    ip:        deviceInfo.ipAddress,
  },
  createdAt:    new Date(),
  lastActivity: new Date(),
  expiresAt:    new Date(Date.now() + expiryToSeconds(jwtConfig.refreshExpiry) * 1000),
  ipAddress:    deviceInfo.ipAddress,
  userAgent:    deviceInfo.userAgent,
  isActive:     true,
});

// ─── Register ────────────────────────────────────────────────────────────────

exports.register = async (req, res, next) => {
  // Explicitly exclude server-controlled fields so a caller cannot self-assign
  // status, override tenantId, inject internal fields, etc.
  // `role` is allowed through as a role *name* string and resolved below.
  const {
    email, password, username, firstName, lastName,
    role: roleName,
    status: _status, isActive: _isActive, isDeleted: _isDeleted,
    tenantId: _tid, hash_password: _hp, emailVerificationToken: _evt,
    emailVerificationTokenExpiry: _evte, loginSecurity: _ls,
    sessions: _sessions, ...rest
  } = req.body;
  const tenantId = req.tenantId;
  const deviceInfo = DeviceDetector.detectDevice(req);

  // Check password strength
  const { isValid, feedback } = checkPasswordStrength(password);
  if (!isValid) return next(AppError.badRequest('Password does not meet requirements', feedback));

  // Check existing user
  const existing = await User.findOne({ tenantId, email: email.toLowerCase() });
  if (existing) return next(AppError.conflict('Email is already registered'));

  const usernameToUse = username || email.split('@')[0];
  const existingUser  = await User.findOne({ tenantId, username: usernameToUse });
  if (existingUser) return next(AppError.conflict(`Username "${usernameToUse}" is already taken`));

  // Resolve role: use the requested role name if provided and found, otherwise fall back to the tenant's default role
  const defaultRole = await Role.findOne({ tenantId, isDefault: true });
  let resolvedRole = defaultRole;
  if (roleName && typeof roleName === 'string') {
    const requestedRole = await Role.findOne({ tenantId, name: roleName.trim(), isActive: true, isDeleted: false });
    if (requestedRole) resolvedRole = requestedRole;
    // If the requested role doesn't exist, silently fall back to the default
  }

  // Create user
  const hash_password = await hashPassword(password);
  const verifyToken   = generateSecureToken(32);
  const verifyHash    = hashToken(verifyToken);

  const user = await User.create({
    tenantId,
    email: email.toLowerCase(),
    username: usernameToUse,
    hash_password,
    firstName: firstName || null,
    lastName:  lastName  || null,
    emailVerificationToken:       verifyHash,
    emailVerificationTokenExpiry: new Date(Date.now() + EMAIL_VERIFY_EXPIRY_HOURS * 60 * 60 * 1000),
    role:     resolvedRole?._id || null,
    status: 'pending',
    isActive: true,
    ...rest,
  });

  // Log event + fire-and-forget emails: welcome to user, notification to admin
  activityLog.logRegistration(user, req);
  const verifyLink = `${env.FRONTEND_URL}/verify-email?token=${verifyToken}&tenantId=${tenantId}`;
  emailNotifier.send(emailPayloads.welcome(user, verifyLink));
  if (env.ADMIN_EMAIL) {
    emailNotifier.send(emailPayloads.adminUserRegistered(user, req));
  }

  return sendCreated(res, 'Registration successful. Please verify your email.', {
    user: { id: user.id, email: user.email, username: user.username, status: user.status },
  });
};

// ─── Login ───────────────────────────────────────────────────────────────────

exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  const tenantId   = req.tenantId;
  const deviceInfo = DeviceDetector.detectDevice(req);

  const user = await User.findOne({ tenantId, email: email.toLowerCase() }).populate('role');

  // Constant-time response to prevent email enumeration
  if (!user) {
    await new Promise((r) => setTimeout(r, 300));
    return next(AppError.unauthorized('Invalid email or password'));
  }

  // Account status checks
  if (user.isDeleted || !user.isActive || user.status === 'banned')
    return next(AppError.unauthorized('Account is not accessible'));
  if (user.status === 'suspended')
    return next(AppError.forbidden('Account has been suspended'));

  // Lockout check
  if (user.isLocked) {
    const lockExpiry = user.loginSecurity.lockedUntil;
    return next(AppError.locked(`Account is locked until ${lockExpiry.toISOString()}`));
  }

  // Password verification
  const passwordMatch = await user.comparePassword(password);
  if (!passwordMatch) {
    await user.incrementFailedLogin();
    activityLog.logFailedLogin(email, req, 'INVALID_PASSWORD');

    if (user.loginSecurity.failedAttempts >= MAX_LOGIN_ATTEMPTS) {
      emailNotifier.send(emailPayloads.accountLocked(user));
      return next(AppError.locked('Account locked due to too many failed attempts'));
    }

    emailNotifier.send(emailPayloads.loginFailed(user, deviceInfo.ipAddress));
    return next(AppError.unauthorized('Invalid email or password'));
  }

  // Check if MFA required
  if (user.twoFactorAuth?.enabled && user.twoFactorAuth?.setupCompleted) {
    const mfaToken = uuidv4();
    // Store mfa token info temporarily in user doc (short-lived)
    user.currentOTP = {
      hashedCode:  hashToken(mfaToken),
      type:        'backup',
      purpose:     'login',
      expiresAt:   new Date(Date.now() + 5 * 60 * 1000), // 5 min
      attempts:    0,
      maxAttempts: 3,
      lastSent:    new Date(),
      verified:    false,
    };
    await user.save();
    return sendSuccess(res, 'MFA verification required', {
      twoFactorRequired: true,
      mfaToken,
    });
  }

  // Issue tokens
  const session = buildSession(deviceInfo);
  user.activeSessions.push(session);
  await user.resetFailedLogin();

  const { accessToken, accessJti, refreshToken, refreshJti, idToken } = generateTokens(user, session.sessionId);

  // Store hashed refresh jti
  user.refreshTokens.push({
    jti:      hashToken(refreshJti),
    createdAt: new Date(),
    expiresAt: session.expiresAt,
    userAgent: deviceInfo.userAgent,
    ipAddress: deviceInfo.ipAddress,
    isActive:  true,
  });
  await user.save();

  setCookiesOnHeader(res, accessToken, refreshToken, idToken);

  // Track new device
  const knownDevice = user.knownDevices.find((d) => d.deviceId === deviceInfo.deviceId);
  if (!knownDevice) {
    user.knownDevices.push({
      deviceId: deviceInfo.deviceId, fingerprint: deviceInfo.fingerprint,
      type: deviceInfo.device?.type, os: deviceInfo.os?.name,
      browser: deviceInfo.browser?.name, firstSeen: new Date(), lastSeen: new Date(),
      ipAddress: deviceInfo.ipAddress, isTrusted: false, isActive: true,
    });
    await user.save();
    emailNotifier.send(emailPayloads.newDeviceLogin(user, {
      device: `${deviceInfo.browser?.name} on ${deviceInfo.os?.name}`,
      location: deviceInfo.location?.city || 'Unknown',
      ip: deviceInfo.ipAddress,
    }));
  }

  activityLog.logLogin(user, req, session.sessionId, 'password');

  return sendSuccess(res, 'Login successful', {
    accessToken,
    accessExpiresIn: expiryToSeconds(jwtConfig.accessExpiry),
    refreshToken,
    refreshExpiresIn: expiryToSeconds(jwtConfig.refreshExpiry),
  });
};

// ─── MFA Login Verification ───────────────────────────────────────────────────

exports.verifyMfaLogin = async (req, res, next) => {
  const { mfaToken, totpCode, backupCode } = req.body;
  const tenantId = req.tenantId;

  // Find session-level MFA state — user is identified by hashed mfaToken in currentOTP
  const hashedToken = hashToken(mfaToken);
  const user = await User.findOne({ tenantId, 'currentOTP.hashedCode': hashedToken, 'currentOTP.purpose': 'login' }).populate('role');
  if (!user) return next(AppError.unauthorized('Invalid or expired MFA session'));

  if (!user.currentOTP || new Date() > user.currentOTP.expiresAt)
    return next(AppError.unauthorized('MFA session expired'));

  let verified = false;
  if (totpCode) {
    verified = otpService.verifyTOTP(user, String(totpCode));
  } else if (backupCode) {
    verified = await otpService.useBackupCode(user, String(backupCode));
  }

  if (!verified) return next(AppError.unauthorized('Invalid MFA code'));

  // Clear MFA state
  user.currentOTP = {};
  const deviceInfo = DeviceDetector.detectDevice(req);
  const session    = buildSession(deviceInfo);
  user.activeSessions.push(session);
  await user.resetFailedLogin();

  const { accessToken, refreshJti, refreshToken, idToken } = generateTokens(user, session.sessionId);
  user.refreshTokens.push({
    jti: hashToken(refreshJti), createdAt: new Date(), expiresAt: session.expiresAt,
    userAgent: deviceInfo.userAgent, ipAddress: deviceInfo.ipAddress, isActive: true,
  });
  await user.save();

  setCookiesOnHeader(res, accessToken, refreshToken, idToken);
  activityLog.logLogin(user, req, session.sessionId, 'totp');

  return sendSuccess(res, 'Login successful', {
    accessToken,
    accessExpiresIn: expiryToSeconds(jwtConfig.accessExpiry),
    refreshToken,
    refreshExpiresIn: expiryToSeconds(jwtConfig.refreshExpiry),
  });
};

// ─── Logout ───────────────────────────────────────────────────────────────────

exports.logout = async (req, res, next) => {
  const accessToken  = req.headers.authorization?.split(' ')[1];
  const refreshCookie = req.cookies?.refreshToken;
  const tenantId     = req.tenantId;
  const user         = req.user;

  // Revoke access token jti
  if (accessToken) {
    try {
      const decoded = verifyAccessToken(accessToken);
      const ttl     = Math.max(0, Math.floor((decoded.exp * 1000 - Date.now()) / 1000));
      await revokeToken(decoded.jti, tenantId, user?._id?.toString(), ttl, 'logout');
    } catch { /* already expired — safe to ignore */ }
  }

  // Revoke refresh token
  if (refreshCookie) {
    try {
      const decoded = verifyRefreshToken(refreshCookie);
      const ttl     = Math.max(0, Math.floor((decoded.exp * 1000 - Date.now()) / 1000));
      await revokeToken(decoded.jti, tenantId, user?._id?.toString(), ttl, 'logout');
    } catch { /* ignore */ }
  }

  // Mark session inactive
  if (user && req.sessionId) {
    const session = user.activeSessions.find((s) => s.sessionId === req.sessionId);
    if (session) { session.isActive = false; await user.save(); }
    activityLog.logLogout(user, req, req.sessionId);
  }

  clearAuthCookies(res);
  return sendSuccess(res, 'Logged out successfully');
};

// ─── Refresh Token ────────────────────────────────────────────────────────────

exports.refreshToken = async (req, res, next) => {
  const token    = req.cookies?.refreshToken || req.body?.refreshToken;
  const tenantId = req.tenantId;

  if (!token) return next(AppError.unauthorized('No refresh token provided'));

  let decoded;
  try {
    decoded = verifyRefreshToken(token);
  } catch (err) {
    if (err.name === 'TokenExpiredError') return next(AppError.unauthorized('Refresh token expired', 'TOKEN_EXPIRED'));
    return next(AppError.unauthorized('Invalid refresh token'));
  }

  // Check if revoked
  const revoked = await isTokenRevoked(decoded.jti, tenantId);
  if (revoked) {
    // Possible token reuse — revoke all sessions for safety
    const user = await User.findOne({ _id: decoded.sub, tenantId });
    if (user) await revokeAllUserTokens(user, 'suspicious');
    return next(AppError.unauthorized('Refresh token reuse detected. All sessions revoked.', 'REFRESH_TOKEN_REUSED'));
  }

  const user = await User.findOne({ _id: decoded.sub, tenantId }).populate('role');
  if (!user || !user.isActive || user.isDeleted) return next(AppError.unauthorized('User not found or inactive'));

  // Immediately revoke old refresh token
  const oldTtl = Math.max(0, Math.floor((decoded.exp * 1000 - Date.now()) / 1000));
  await revokeToken(decoded.jti, tenantId, user._id.toString(), oldTtl, 'logout');

  // Issue new token pair
  const session = buildSession(DeviceDetector.detectDevice(req));
  user.activeSessions.push(session);

  const { accessToken, refreshJti, refreshToken: newRefreshToken, idToken } = generateTokens(user, session.sessionId);
  user.refreshTokens.push({
    jti: hashToken(refreshJti), createdAt: new Date(), expiresAt: session.expiresAt,
    userAgent: req.headers['user-agent'], ipAddress: req.ip, isActive: true,
  });
  await user.save();

  setCookiesOnHeader(res, accessToken, newRefreshToken, idToken);
  return sendSuccess(res, 'Token refreshed', {
    accessToken,
    accessExpiresIn:  expiryToSeconds(jwtConfig.accessExpiry),
    refreshToken:     newRefreshToken,
    refreshExpiresIn: expiryToSeconds(jwtConfig.refreshExpiry),
  });
};

// ─── Verify Token (used by other microservices) ───────────────────────────────
// Returns 200 { valid: true|false } always so gateway services get a consistent
// shape.  On success the full live user record is returned (not just JWT claims),
// guaranteeing downstream services see the current role and permissions even
// when the token was issued before a role change.

exports.verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ valid: false, error: 'NO_TOKEN' });
  }
  const token = authHeader.split(' ')[1];

  try {
    const decoded = verifyAccessToken(token);
    const tenantId = req.tenantId || decoded.tenantId;

    // Cross-tenant check — pure in-memory, reject before any DB call
    if (req.tenantId && decoded.tenantId !== req.tenantId) {
      return res.status(403).json({ valid: false, error: 'TENANT_MISMATCH' });
    }

    // Run revocation check and user fetch in parallel — they are independent
    const [revoked, user] = await Promise.all([
      isTokenRevoked(decoded.jti, tenantId),
      User.findOne(
        { _id: decoded.sub, tenantId, isDeleted: false },
        'status isActive activeSessions',
        { lean: true }
      ),
    ]);

    if (revoked) return res.status(401).json({ valid: false, error: 'TOKEN_REVOKED' });
    if (!user) return res.status(401).json({ valid: false, error: 'USER_NOT_FOUND' });
    if (!user.isActive || user.status !== 'active') {
      return res.status(401).json({ valid: false, error: 'ACCOUNT_INACTIVE' });
    }

    // Verify the session referenced in the token is still active
    const sessionActive = user.activeSessions.some(
      (s) => s.sessionId === decoded.sessionId && s.isActive && s.expiresAt > new Date()
    );
    if (!sessionActive) return res.status(401).json({ valid: false, error: 'SESSION_INVALID' });

    return res.status(200).json({
      valid:     true,
      id:        decoded.sub,
      role:      decoded.role,
      sessionId: decoded.sessionId,
    });
  } catch (err) {
    const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    return res.status(401).json({ valid: false, error: code });
  }
};

// ─── Email Verification ───────────────────────────────────────────────────────

exports.verifyEmail = async (req, res, next) => {
  const { token } = req.body;
  const tenantId  = req.tenantId;
  if (!token) return next(AppError.badRequest('Verification token is required'));

  const hashedToken = hashToken(token);
  const user = await User.findOne({
    tenantId,
    emailVerificationToken:       hashedToken,
    emailVerificationTokenExpiry: { $gt: new Date() },
    emailVerified: false,
  });

  if (!user) return next(AppError.badRequest('Invalid or expired verification token'));

  user.emailVerified              = true;
  user.isVerified                 = true;
  user.status                     = 'active';
  user.emailVerificationToken     = null;
  user.emailVerificationTokenExpiry = null;
  await user.save();

  emailNotifier.send(emailPayloads.emailVerified(user));
  return sendSuccess(res, 'Email verified successfully');
};

exports.resendVerification = async (req, res, next) => {
  const { email } = req.body;
  const tenantId  = req.tenantId;
  if (!email) return next(AppError.badRequest('Email is required'));

  // Always 200 to prevent enumeration
  const user = await User.findOne({ tenantId, email: email.toLowerCase(), emailVerified: false });
  if (user) {
    const verifyToken = generateSecureToken(32);
    user.emailVerificationToken       = hashToken(verifyToken);
    user.emailVerificationTokenExpiry = new Date(Date.now() + EMAIL_VERIFY_EXPIRY_HOURS * 60 * 60 * 1000);
    await user.save();
    const verifyLink = `${env.FRONTEND_URL}/verify-email?token=${verifyToken}&tenantId=${tenantId}`;
    emailNotifier.send(emailPayloads.emailVerificationLink(user, verifyLink));
  }

  return sendSuccess(res, 'If that email exists and is unverified, a new verification link has been sent.');
};

// ─── Password: Forgot ─────────────────────────────────────────────────────────

exports.forgotPassword = async (req, res, next) => {
  logger.info('Password reset requested', { email: req.body.email, tenantId: req.tenantId });
  const { email } = req.body;
  const tenantId  = req.tenantId;

  // Always 200 — never reveal whether email exists
  const user = await User.findOne({ tenantId, email: email.toLowerCase() });
  if (user) {
    const resetToken = generateSecureToken(32);
    user.passwordReset.token      = hashToken(resetToken);
    user.passwordReset.tokenExpiry = new Date(Date.now() + PASSWORD_RESET_EXPIRY_HOURS * 60 * 60 * 1000);
    user.passwordReset.attempts   = 0;
    await user.save();
    const resetLink = `${env.FRONTEND_URL}/reset-password?token=${resetToken}&tenantId=${tenantId}`;
    emailNotifier.send(emailPayloads.passwordResetRequested(user, resetLink));
  }

  return sendSuccess(res, 'If that email is registered, you will receive a password reset link.');
};

// ─── Password: Reset ──────────────────────────────────────────────────────────

exports.resetPassword = async (req, res, next) => {
  const { token, password } = req.body;
  const tenantId = req.tenantId;
  if (!token || !password) return next(AppError.badRequest('Token and password are required'));

  const { isValid, feedback } = checkPasswordStrength(password);
  if (!isValid) return next(AppError.badRequest('Password does not meet requirements', feedback));

  const hashedToken = hashToken(token);
  const user = await User.findOne({
    tenantId,
    'passwordReset.token': hashedToken,
    'passwordReset.tokenExpiry': { $gt: new Date() },
  });
  if (!user) return next(AppError.badRequest('Invalid or expired reset token'));

  user.hash_password        = await hashPassword(password);
  user.passwordReset.token  = null;
  user.passwordReset.tokenExpiry = null;
  user.passwordReset.attempts    = 0;
  await revokeAllUserTokens(user, 'password_change');
  await user.save();

  emailNotifier.send(emailPayloads.passwordResetCompleted(user));
  return sendSuccess(res, 'Password has been reset. Please log in again.');
};

// ─── Password: Change ─────────────────────────────────────────────────────────

exports.changePassword = async (req, res, next) => {
  const { currentPassword, password } = req.body;
  const tenantId = req.tenantId;
  const user     = await User.findOne({ _id: req.user._id, tenantId }).populate('role');

  const match = await user.comparePassword(currentPassword);
  if (!match) return next(AppError.badRequest('Current password is incorrect'));

  const { isValid, feedback } = checkPasswordStrength(password);
  if (!isValid) return next(AppError.badRequest('Password does not meet requirements', feedback));

  user.hash_password = await hashPassword(password);
  await revokeAllUserTokens(user, 'password_change');
  await user.save();

  // Re-issue tokens so current device stays logged in
  const deviceInfo = DeviceDetector.detectDevice(req);
  const session    = buildSession(deviceInfo);
  user.activeSessions.push(session);
  const { accessToken, refreshJti, refreshToken, idToken } = generateTokens(user, session.sessionId);
  user.refreshTokens.push({
    jti: hashToken(refreshJti), createdAt: new Date(), expiresAt: session.expiresAt,
    userAgent: deviceInfo.userAgent, ipAddress: deviceInfo.ipAddress, isActive: true,
  });
  await user.save();
  setCookiesOnHeader(res, accessToken, refreshToken, idToken);

  emailNotifier.send(emailPayloads.passwordChanged(user));
  return sendSuccess(res, 'Password changed successfully', { accessToken });
};

// ─── Profile ──────────────────────────────────────────────────────────────────

// Fields that must never leave the service in any profile response
const PROFILE_EXCLUDE = '-hash_password -emailVerificationToken -emailVerificationTokenExpiry -passwordReset -unlockToken -loginSecurity -refreshTokens -currentOTP -twoFactorAuth -activeSessions -loginHistory -securityEvents -knownDevices -__v';

exports.getProfile = async (req, res, next) => {
  const user = await User.findOne(
    { _id: req.user._id, tenantId: req.tenantId },
    PROFILE_EXCLUDE
  ).populate('role', '_id name');
  if (!user) return next(AppError.notFound('User not found'));
  return sendSuccess(res, 'Profile retrieved', sanitizeUser(user));
};

exports.updateProfile = async (req, res, next) => {
  const ALLOWED = ['firstName', 'lastName', 'username', 'phoneNumber', 'dateOfBirth', 'gender', 'profilePicture'];
  const updates = {};
  ALLOWED.forEach((f) => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });

  if (!Object.keys(updates).length) {
    return next(AppError.badRequest('No updatable fields provided'));
  }

  // Username uniqueness check (tenant-scoped)
  if (updates.username) {
    const taken = await User.exists({
      tenantId: req.tenantId,
      username: updates.username,
      _id: { $ne: req.user._id },
    });
    if (taken) return next(AppError.conflict('Username is already taken'));
  }

  // Snapshot sensitive fields before update so we can detect what changed
  const before = await User.findOne(
    { _id: req.user._id, tenantId: req.tenantId },
    'username phoneNumber'
  ).lean();

  const user = await User.findOneAndUpdate(
    { _id: req.user._id, tenantId: req.tenantId },
    { $set: { ...updates, updatedBy: req.user._id } },
    { new: true, runValidators: true, projection: PROFILE_EXCLUDE }
  ).populate('role', '_id name');
  if (!user) return next(AppError.notFound('User not found'));

  // Fire-and-forget activity log
  activityLog.log(activityLog.fromRequest(req, {
    action:      'PROFILE_UPDATED',
    operation:   'update',
    description: `User ${user.email} updated profile`,
    entity:      'User',
    entityId:    user._id,
    status:      'success',
    metadata:    { updatedFields: Object.keys(updates) },
  }));

  // Notify user of security-relevant field changes (fire-and-forget)
  if (updates.phoneNumber !== undefined && updates.phoneNumber !== before?.phoneNumber) {
    emailNotifier.send(emailPayloads.phoneChanged(user));
  }
  if (updates.username !== undefined && updates.username !== before?.username) {
    emailNotifier.send(emailPayloads.usernameChanged(user, before?.username));
  }

  return sendSuccess(res, 'Profile updated', sanitizeUser(user));
};

// ─── Sessions ─────────────────────────────────────────────────────────────────

exports.getSessions = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  const sessions = (user?.activeSessions || []).filter((s) => s.isActive).map(stripId);
  return sendSuccess(res, 'Active sessions', sessions);
};

exports.revokeSession = async (req, res, next) => {
  const { sessionId } = req.params;
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  const session = user?.activeSessions.find((s) => s.sessionId === sessionId && s.isActive);
  if (!session) return next(AppError.notFound('Session not found'));
  session.isActive = false;
  await user.save();
  return sendSuccess(res, 'Session revoked');
};

exports.revokeAllSessions = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));
  await revokeAllUserTokens(user, 'revoked_all');
  emailNotifier.send(emailPayloads.logoutAllDevices(user));
  clearAuthCookies(res);
  return sendSuccess(res, 'All sessions revoked');
};

// ─── Devices ──────────────────────────────────────────────────────────────────

exports.getDevices = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  const devices = (user?.knownDevices || []).filter((d) => d.isActive).map(stripId);
  return sendSuccess(res, 'Known devices', devices);
};

exports.removeDevice = async (req, res, next) => {
  const { deviceId } = req.params;
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  const device = user?.knownDevices.find((d) => d.deviceId === deviceId);
  if (!device) return next(AppError.notFound('Device not found'));
  device.isActive = false;
  await user.save();
  return sendSuccess(res, 'Device removed');
};

// ─── TOTP / MFA ───────────────────────────────────────────────────────────────

exports.setupTotp = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));
  if (user.twoFactorAuth?.enabled) return next(AppError.conflict('TOTP is already enabled'));
  const result = await otpService.setupTOTP(user);
  emailNotifier.send(emailPayloads.twoFactorSetup(user, result.qrCodeUrl, result.secret));
  return sendSuccess(res, 'TOTP setup initialized. Scan the QR code with your authenticator app.', result);
};

exports.verifyTotpSetup = async (req, res, next) => {
  const { code } = req.body;
  if (!code) return next(AppError.badRequest('TOTP code is required'));
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));
  const verified = await otpService.verifyTOTPSetup(user, String(code));
  if (!verified) return next(AppError.badRequest('Invalid TOTP code'));
  const codes = user.twoFactorAuth.backupCodes.map((b) => b.code);
  emailNotifier.send(emailPayloads.mfaEnabled(user));
  emailNotifier.send(emailPayloads.backupCodes(user, codes));
  return sendSuccess(res, 'TOTP enabled. Store your backup codes in a safe place.', {
    backupCodes: codes,
    warning: 'Each backup code can only be used once. Store them securely — treat them like passwords.',
  });
};

exports.disableTotp = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));
  user.twoFactorAuth.enabled        = false;
  user.twoFactorAuth.setupCompleted = false;
  user.twoFactorAuth.secret         = null;
  await user.save();
  emailNotifier.send(emailPayloads.mfaDisabled(user));
  return sendSuccess(res, 'TOTP disabled');
};

exports.getBackupCodes = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  const codes = user?.twoFactorAuth?.backupCodes?.filter((b) => !b.used).map((b) => b.code) || [];
  return sendSuccess(res, 'Backup codes', { backupCodes: codes, remaining: codes.length });
};

exports.regenerateBackupCodes = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));
  if (!user.twoFactorAuth?.enabled) return next(AppError.badRequest('TOTP is not enabled'));
  user.twoFactorAuth.backupCodes = otpService._generateBackupCodes(10);
  await user.save();
  const codes = user.twoFactorAuth.backupCodes.map((b) => b.code);
  emailNotifier.send(emailPayloads.backupCodes(user, codes));
  return sendSuccess(res, 'Backup codes regenerated. Store your new codes in a safe place.', {
    backupCodes: codes,
    warning: 'Your previous backup codes have been invalidated. Each new code can only be used once.',
  });
};

// ─── OTP ──────────────────────────────────────────────────────────────────────

exports.verifyOtp = async (req, res, next) => {
  const { userId, code, purpose } = req.body;
  const tenantId = req.tenantId;
  if (!userId || !code) return next(AppError.badRequest('userId and code are required'));

  const user = await User.findOne({ _id: userId, tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  const result = await otpService.verifyOTP(user, code, purpose);
  if (!result.valid) return next(AppError.badRequest(result.reason || 'Invalid OTP code'));

  req.otpVerified = true;
  return sendSuccess(res, 'OTP verified successfully');
};

exports.resendOtp = async (req, res, next) => {
  const { userId, purpose, method } = req.body;
  const tenantId = req.tenantId;
  if (!userId) return next(AppError.badRequest('userId is required'));

  const VALID_METHODS = ['totp', 'email', 'sms'];
  if (method && !VALID_METHODS.includes(method)) {
    return next(AppError.badRequest(`Invalid OTP method. Must be one of: ${VALID_METHODS.join(', ')}`));
  }

  const user = await User.findOne({ _id: userId, tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  const result = await otpService.generateAndSend(user, purpose || 'login', method);
  return sendSuccess(res, 'OTP sent', { method: result.method, destination: result.maskedDestination });
};

// ─── Phone Verification ───────────────────────────────────────────────────────

exports.verifyPhone = async (req, res, next) => {
  const { code } = req.body;
  const user     = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  const result = await otpService.verifyOTP(user, code, 'verification');
  if (!result.valid) return next(AppError.badRequest(result.reason || 'Invalid OTP'));

  user.phoneVerified = true;
  await user.save();
  return sendSuccess(res, 'Phone verified');
};

exports.resendPhoneOtp = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));
  if (!user.phoneNumber) return next(AppError.badRequest('No phone number on file'));
  const result = await otpService.generateAndSend(user, 'verification', 'sms');
  return sendSuccess(res, 'OTP sent to phone', { destination: result.maskedDestination });
};

// ─── GDPR / Account self-service ──────────────────────────────────────────────

exports.deleteOwnAccount = async (req, res, next) => {
  const { password } = req.body;

  // Require current password for accounts that have one — prevents XSS/CSRF account wipeout
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  if (user.hash_password) {
    if (!password) return next(AppError.badRequest('Password is required to delete your account'));
    const match = await user.comparePassword(password);
    if (!match) return next(AppError.unauthorized('Incorrect password'));
  }

  // Capture email before anonymization so the farewell email can be sent
  const originalEmail = user.email;
  const originalName  = user.firstName || user.username;

  // Anonymize PII
  const anonId = `deleted_${Date.now()}`;
  user.email         = `${anonId}@deleted.invalid`;
  user.username      = anonId;
  user.firstName     = null;
  user.lastName      = null;
  user.phoneNumber   = null;
  user.isDeleted     = true;
  user.isActive      = false;
  user.status        = 'inactive';
  user.hash_password = null;
  user.socialAccounts = [];
  user.knownDevices   = [];
  user.deletedBy     = req.user._id;
  user.deletedAt     = new Date();

  await revokeAllUserTokens(user, 'revoked_all');
  await user.save();

  emailNotifier.send(emailPayloads.accountDeleted({ email: originalEmail, firstName: originalName }));
  clearAuthCookies(res);
  return sendSuccess(res, 'Account deleted. All your data has been anonymized.');
};

exports.exportAccountData = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId })
    .populate('role', '_id name')
    .select('-hash_password -passwordReset -emailVerificationToken -emailVerificationTokenExpiry -twoFactorAuth -currentOTP');
  if (!user) return next(AppError.notFound('User not found'));
  const data = user.toObject();
  // Reduce populated role to just name string for consistency
  if (data.role && typeof data.role === 'object' && data.role.name !== undefined) {
    data.role = data.role.name;
  }
  return sendSuccess(res, 'Account data export', { user: data });
};

// ─── Self-Service Account Unlock ─────────────────────────────────────────────────────

// POST /api/auth/account/unlock/request  — public, no JWT needed
// Always returns 200 to prevent account-existence enumeration.
exports.requestAccountUnlock = async (req, res, next) => {
  const { email } = req.body;
  const tenantId  = req.tenantId;
  if (!email) return next(AppError.badRequest('Email is required'));

  const user = await User.findOne({ tenantId, email: email.toLowerCase() });
  if (user && user.loginSecurity?.lockedUntil) {
    const unlockToken = generateSecureToken(32);
    user.unlockToken.token       = hashToken(unlockToken);
    user.unlockToken.tokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();
    const unlockLink = `${env.FRONTEND_URL}/unlock-account?token=${unlockToken}&email=${encodeURIComponent(user.email)}&tenantId=${tenantId}`;
    emailNotifier.send(emailPayloads.accountUnlockRequest(user, unlockLink));
  }

  return sendSuccess(res, 'If your account is locked, you will receive an unlock link via email.');
};

// POST /api/auth/account/unlock/confirm  — public, no JWT needed
exports.confirmAccountUnlock = async (req, res, next) => {
  const { email, token } = req.body;
  const tenantId = req.tenantId;
  if (!email || !token) return next(AppError.badRequest('Email and token are required'));

  const hashedToken = hashToken(token);
  const user = await User.findOne({
    tenantId,
    email: email.toLowerCase(),
    'unlockToken.token':       hashedToken,
    'unlockToken.tokenExpiry': { $gt: new Date() },
  });
  if (!user) return next(AppError.badRequest('Invalid or expired unlock token'));

  user.unlockToken.token       = null;
  user.unlockToken.tokenExpiry = null;
  await user.resetFailedLogin();

  emailNotifier.send(emailPayloads.accountUnlockConfirmed(user));
  return sendSuccess(res, 'Account unlocked. You may now log in.');
};

// ─── OTP / MFA Settings ──────────────────────────────────────────────────────────────────

// PATCH /api/auth/otp/settings  — JWT required
exports.updateOtpSettings = async (req, res, next) => {
  const ALLOWED_METHODS = ['totp', 'email', 'sms'];
  const { preferredMethod, requireForLogin, requireForSensitiveOps } = req.body;

  if (preferredMethod !== undefined && !ALLOWED_METHODS.includes(preferredMethod)) {
    return next(AppError.badRequest(`preferredMethod must be one of: ${ALLOWED_METHODS.join(', ')}`));
  }

  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  if (preferredMethod   !== undefined) user.otpSettings.preferredMethod        = preferredMethod;
  if (requireForLogin   !== undefined) user.otpSettings.requireForLogin        = !!requireForLogin;
  if (requireForSensitiveOps !== undefined) user.otpSettings.requireForSensitiveOps = !!requireForSensitiveOps;

  await user.save();
  return sendSuccess(res, 'OTP settings updated', { otpSettings: user.otpSettings });
};

// ─── Device Trust Toggle ───────────────────────────────────────────────────────────────────

// PATCH /api/auth/devices/:deviceId/trust  — JWT required
exports.toggleDeviceTrust = async (req, res, next) => {
  const { deviceId } = req.params;
  const { trusted }  = req.body;
  if (typeof trusted !== 'boolean') return next(AppError.badRequest('trusted must be a boolean'));

  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  const device = user.knownDevices.find((d) => d.deviceId === deviceId);
  if (!device) return next(AppError.notFound('Device not found'));

  device.isTrusted = trusted;
  await user.save();
  return sendSuccess(res, `Device ${trusted ? 'trusted' : 'untrusted'}`, { device: stripId(device) });
};

// ─── Security Events Log (self) ────────────────────────────────────────────────────────────

// GET /api/auth/me/security-events  — JWT required
exports.getSecurityEvents = async (req, res, next) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const skip  = parseInt(req.query.skip, 10) || 0;

  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId })
    .select('securityEvents');
  if (!user) return next(AppError.notFound('User not found'));

  const events = [...(user.securityEvents || [])]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(skip, skip + limit)
    .map(stripId);

  return sendSuccess(res, 'Security events', {
    events,
    total: user.securityEvents.length,
    limit,
    skip,
  });
};
