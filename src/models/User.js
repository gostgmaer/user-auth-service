// src/models/User.js
const mongoose = require('mongoose');
const bcrypt   = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const env        = require('../config/env');

const BCRYPT_ROUNDS  = env.BCRYPT_ROUNDS;
const MAX_ATTEMPTS   = env.MAX_LOGIN_ATTEMPTS;
const LOCK_WINDOW_MS = env.LOCK_WINDOW_MS;

const userSchema = new mongoose.Schema(
  {
    // ─── Multi-tenancy ────────────────────────────────────────────────────
    tenantId: { type: String, required: true, index: true },

    // ─── Identity ─────────────────────────────────────────────────────────
    username:     { type: String, required: true, trim: true, minlength: 3, maxlength: 30 },
    email:        { type: String, required: true, lowercase: true, trim: true },
    hash_password:{ type: String, default: null },

    // ─── Profile ──────────────────────────────────────────────────────────
    firstName:    { type: String, trim: true, default: null },
    lastName:     { type: String, trim: true, default: null },
    dateOfBirth:  { type: Date,   default: null },
    gender: {
      type: String,
      enum: ['male', 'female', 'other', 'prefer_not_to_say'],
      default: null,
    },
    phoneNumber:  { type: String, default: null },
    profilePicture: {
      url:  { type: String, default: null },
      name: { type: String, default: null },
    },

    // ─── Status & Role ────────────────────────────────────────────────────
    role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role', default: null },
    isActive:  { type: Boolean, default: true },
    isDeleted: { type: Boolean, default: false },
    status:    { type: String, enum: ['active', 'inactive', 'suspended', 'pending', 'banned'], default: 'pending' },
    // ─── Audit Metadata ───────────────────────────────────────────────────────
    // createdBy: null = self-registration; ObjectId = admin-created account
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    deletedAt: { type: Date, default: null },
    // ─── Verification ─────────────────────────────────────────────────────
    emailVerified: { type: Boolean, default: false },
    phoneVerified: { type: Boolean, default: false },
    isVerified:    { type: Boolean, default: false },
    emailVerificationToken: { type: String, default: null },
    emailVerificationTokenExpiry: { type: Date, default: null },

    // ─── Password Reset ───────────────────────────────────────────────────
    passwordReset: {
      token:     { type: String, default: null },   // bcrypt-hashed reset token
      tokenExpiry: { type: Date, default: null },
      attempts:  { type: Number, default: 0 },
      lastAttempt: { type: Date, default: null },
    },

    // ─── Self-Service Account Unlock ──────────────────────────────────────
    unlockToken: {
      token:       { type: String, default: null }, // bcrypt-hashed unlock token
      tokenExpiry: { type: Date,   default: null },
    },

    // ─── Login Security ───────────────────────────────────────────────────
    loginSecurity: {
      failedAttempts:      { type: Number, default: 0 },
      lockedUntil:         { type: Date,   default: null },
      lastLoginAttempt:    { type: Date,   default: null },
      consecutiveFailures: { type: Number, default: 0 },
      suspiciousActivityDetected: { type: Boolean, default: false },
    },
    lastLogin: { type: Date, default: null },
    loginHistory: [
      {
        loginTime:    { type: Date,    default: Date.now },
        ipAddress:    { type: String,  default: null },
        userAgent:    { type: String,  default: null },
        successful:   { type: Boolean, required: true },
        failureReason:{ type: String,  default: null },
        deviceId:     { type: String,  default: null },
        loginMethod:  { type: String,  enum: ['password', 'social', 'otp', 'sso'], default: 'password' },
        location:     { type: mongoose.Schema.Types.Mixed, default: {} },
        browser:      { type: mongoose.Schema.Types.Mixed, default: {} },
        os:           { type: mongoose.Schema.Types.Mixed, default: {} },
        device:       { type: mongoose.Schema.Types.Mixed, default: {} },
        security:     { type: mongoose.Schema.Types.Mixed, default: {} },
      },
    ],

    // ─── Sessions ─────────────────────────────────────────────────────────
    activeSessions: [
      {
        sessionId: { type: String, required: true },
        deviceId:  { type: String, required: true },
        deviceInfo:{ type: mongoose.Schema.Types.Mixed, default: {} },
        createdAt: { type: Date, default: Date.now },
        lastActivity: { type: Date, default: Date.now },
        expiresAt: { type: Date, required: true },
        ipAddress: { type: String, default: null },
        userAgent: { type: String, default: null },
        isActive:  { type: Boolean, default: true },
      },
    ],

    // ─── Refresh Tokens ───────────────────────────────────────────────────
    refreshTokens: [
      {
        jti:       { type: String, required: true },          // hashed jti
        createdAt: { type: Date, default: Date.now },
        expiresAt: { type: Date, required: true },
        userAgent: { type: String, default: null },
        ipAddress: { type: String, default: null },
        isActive:  { type: Boolean, default: true },
      },
    ],

    // ─── OTP / MFA ────────────────────────────────────────────────────────
    otpSettings: {
      enabled:           { type: Boolean, default: false },
      preferredMethod:   { type: String, enum: ['totp', 'email', 'sms'], default: 'email' },
      requireForLogin:   { type: Boolean, default: false },
      requireForSensitiveOps: { type: Boolean, default: true },
    },
    currentOTP: {
      code:       { type: String,  default: null },
      hashedCode: { type: String,  default: null },
      type:       { type: String,  enum: ['email', 'sms', 'backup'], default: null },
      purpose:    { type: String,  enum: ['login', 'reset', 'verification', 'setup_verification', 'sensitive_op'], default: null },
      expiresAt:  { type: Date,    default: null },
      attempts:   { type: Number,  default: 0 },
      maxAttempts:{ type: Number,  default: 5 },
      lastSent:   { type: Date,    default: null },
      verified:   { type: Boolean, default: false },
    },
    twoFactorAuth: {
      enabled:        { type: Boolean, default: false },
      secret:         { type: String,  default: null },
      backupCodes: [
        {
          code:    { type: String, required: true },
          used:    { type: Boolean, default: false },
          usedAt:  { type: Date,   default: null },
          createdAt:{ type: Date,  default: Date.now },
        },
      ],
      setupCompleted: { type: Boolean, default: false },
      lastUsed:       { type: Date,    default: null },
    },

    // ─── Devices ──────────────────────────────────────────────────────────
    knownDevices: [
      {
        deviceId:  { type: String, required: true },
        name:      { type: String, default: null },
        type:      { type: String, default: null },
        os:        { type: String, default: null },
        browser:   { type: String, default: null },
        firstSeen: { type: Date,   default: Date.now },
        lastSeen:  { type: Date,   default: Date.now },
        isTrusted: { type: Boolean, default: false },
        isActive:  { type: Boolean, default: true },
        fingerprint: { type: String, default: null },
        ipAddress: { type: String, default: null },
        location:  { type: mongoose.Schema.Types.Mixed, default: {} },
      },
    ],

    // ─── Social Accounts ──────────────────────────────────────────────────
    socialAccounts: [
      {
        provider:    { type: String, required: true },
        providerId:  { type: String, required: true },
        email:       { type: String, default: null },
        displayName: { type: String, default: null },
        avatar:      { type: String, default: null },
        verified:    { type: Boolean, default: false },
        connectedAt: { type: Date, default: Date.now },
      },
    ],

    // ─── Security Events ──────────────────────────────────────────────────
    securityEvents: [
      {
        event:      { type: String, required: true },
        description:{ type: String, default: null },
        severity:   { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
        timestamp:  { type: Date,   default: Date.now },
        ipAddress:  { type: String, default: null },
        userAgent:  { type: String, default: null },
        metadata:   { type: mongoose.Schema.Types.Mixed, default: {} },
      },
    ],

    // ─── Meta (Organisation / Classification) ─────────────────────────────
    // Single key that groups all organisational and categorical attributes.
    // Populated / updated by admins; read-only for regular users.
    meta: {
      // Organisational hierarchy
      department:  { type: String, trim: true, default: null },
      division:    { type: String, trim: true, default: null },
      branch:      { type: String, trim: true, default: null },
      team:        { type: String, trim: true, default: null },
      // Role / position
      jobTitle:    { type: String, trim: true, default: null },
      employeeId:  { type: String, trim: true, default: null },
      // Reporting
      manager:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
      startDate:   { type: Date, default: null },
      // Classification
      category:    { type: String, trim: true, default: null },   // e.g. "contractor", "full-time", "partner"
      tags:        { type: [String], default: [] },               // admin-set labels for segmentation / filtering
      // Tenant-specific extensions (open key-value store)
      customFields:{ type: mongoose.Schema.Types.Mixed, default: {} },
    },
  },
  { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
);

// ─── Compound Indexes ─────────────────────────────────────────────────────────
userSchema.index({ tenantId: 1, email: 1 },    { unique: true });
userSchema.index({ tenantId: 1, username: 1 }, { unique: true });
userSchema.index({ tenantId: 1, status: 1 });
userSchema.index({ tenantId: 1, createdAt: -1 });
userSchema.index({ tenantId: 1, 'socialAccounts.provider': 1, 'socialAccounts.providerId': 1 });
userSchema.index({ tenantId: 1, 'meta.department': 1 });
userSchema.index({ tenantId: 1, 'meta.team': 1 });
userSchema.index({ tenantId: 1, 'meta.tags': 1 });

// ─── Pre-save: cap unbounded subdocument arrays ───────────────────────────────
// Prevents the 16 MB MongoDB document limit from being hit by long-lived accounts
// with many sessions/tokens. Keep only non-expired entries up to the hard caps.
userSchema.pre('save', function (next) {
  const now = new Date();
  const MAX_SESSIONS      = 50;
  const MAX_TOKENS        = 50;
  const MAX_DEVICES       = 30;
  const MAX_LOGIN_HISTORY = 100;

  if (this.activeSessions && this.activeSessions.length > MAX_SESSIONS) {
    this.activeSessions = this.activeSessions
      .filter((s) => s.isActive && s.expiresAt > now)
      .slice(-MAX_SESSIONS);
  }

  if (this.refreshTokens && this.refreshTokens.length > MAX_TOKENS) {
    this.refreshTokens = this.refreshTokens
      .filter((t) => t.isActive && t.expiresAt > now)
      .slice(-MAX_TOKENS);
  }

  if (this.knownDevices && this.knownDevices.length > MAX_DEVICES) {
    this.knownDevices = this.knownDevices
      .filter((d) => d.isActive)
      .slice(-MAX_DEVICES);
  }

  if (this.loginHistory && this.loginHistory.length > MAX_LOGIN_HISTORY) {
    this.loginHistory = this.loginHistory.slice(-MAX_LOGIN_HISTORY);
  }

  next();
});


userSchema.virtual('fullName').get(function () {
  return [this.firstName, this.lastName].filter(Boolean).join(' ') || this.username;
});

userSchema.virtual('hasActiveTOTP').get(function () {
  return !!(this.twoFactorAuth?.enabled && this.twoFactorAuth?.setupCompleted);
});

userSchema.virtual('isLocked').get(function () {
  return !!(this.loginSecurity?.lockedUntil && this.loginSecurity.lockedUntil > new Date());
});

// ─── Instance Methods ─────────────────────────────────────────────────────────
userSchema.methods.comparePassword = function (plain) {
  if (!this.hash_password) return Promise.resolve(false);
  return bcrypt.compare(plain, this.hash_password);
};

userSchema.methods.incrementFailedLogin = async function () {
  this.loginSecurity.failedAttempts      = (this.loginSecurity.failedAttempts || 0) + 1;
  this.loginSecurity.consecutiveFailures = (this.loginSecurity.consecutiveFailures || 0) + 1;
  this.loginSecurity.lastLoginAttempt    = new Date();

  if (this.loginSecurity.failedAttempts >= MAX_ATTEMPTS) {
    this.loginSecurity.lockedUntil = new Date(Date.now() + LOCK_WINDOW_MS);
  }
  return this.save();
};

userSchema.methods.resetFailedLogin = async function () {
  this.loginSecurity.failedAttempts      = 0;
  this.loginSecurity.consecutiveFailures = 0;
  this.loginSecurity.lockedUntil         = null;
  this.lastLogin = new Date();
  return this.save();
};

userSchema.methods.logSecurityEvent = async function (event, description, severity = 'medium', meta = {}) {
  this.securityEvents.push({ event, description, severity, metadata: meta, timestamp: new Date() });
  // Keep only last 100 events
  if (this.securityEvents.length > 100) {
    this.securityEvents = this.securityEvents.slice(-100);
  }
  return this.save();
};

// ─── Static Methods ───────────────────────────────────────────────────────────
userSchema.statics.findByEmail = function (tenantId, email) {
  return this.findOne({ tenantId, email: email.toLowerCase() });
};

userSchema.statics.registerNewUser = async function (data, tenantId) {
  const { email, username, password, ...rest } = data;
  const hash_password = await bcrypt.hash(password, BCRYPT_ROUNDS);
  return this.create({
    tenantId,
    email: email.toLowerCase(),
    username: username || email.split('@')[0],
    hash_password,
    status: 'pending',
    ...rest,
  });
};

const User = mongoose.model('User', userSchema);
module.exports = User;
