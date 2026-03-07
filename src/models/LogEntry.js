// src/models/LogEntry.js
const mongoose = require('mongoose');

const logEntrySchema = new mongoose.Schema(
  {
    tenantId: { type: String, required: true, index: true },

    // Actor
    userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role:      { type: String, enum: ['super_admin', 'admin', 'manager', 'staff', 'vendor', 'customer', 'guest', 'support_agent', 'moderator', 'user', 'system'], default: 'user' },
    sessionId: { type: String, default: null },

    // Action
    action:      { type: String, required: true },
    operation:   { type: String, enum: ['create', 'update', 'delete', 'read', 'remove'], required: true },
    description: { type: String, default: null },
    entity:      { type: String, default: null },
    entityId:    { type: mongoose.Schema.Types.ObjectId, default: null },

    // Request metadata
    ipAddress:  { type: String, default: null },
    userAgent:  { type: String, default: null },
    endpoint:   { type: String, default: null },
    httpMethod: { type: String, enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], default: null },

    // Geo + Device
    location: {
      country: { type: String, default: null },
      region:  { type: String, default: null },
      city:    { type: String, default: null },
      lat:     { type: Number, default: null },
      lng:     { type: Number, default: null },
    },
    device: {
      os:         { type: String, default: null },
      browser:    { type: String, default: null },
      deviceType: {
        type: String,
        enum: ['desktop', 'mobile', 'tablet', 'bot', 'unknown'],
        default: 'unknown',
      },
    },

    // Status
    status:       { type: String, enum: ['success', 'failure', 'pending'], default: 'success' },
    errorCode:    { type: String, default: null },
    errorMessage: { type: String, default: null },

    // Metadata
    metadata:    { type: Object, default: {} },
    sensitive:   { type: Boolean, default: false },
    retentionPolicy: {
      type: String,
      enum: ['30d', '90d', '1y', 'forever'],
      default: '1y',
    },
    // Computed from retentionPolicy in pre-save hook.
    // MongoDB TTL index uses this field to auto-delete documents.
    // Null means the document lives forever (MongoDB skips null in TTL scans).
    expiresAt: { type: Date, default: null },
    isDeleted: { type: Boolean, default: false },
  },
  {
    timestamps: true,
    toJSON:   { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ─── TTL Index ────────────────────────────────────────────────────────────────
// MongoDB auto-deletes documents once expiresAt is in the past.
// expireAfterSeconds: 0 means delete exactly at expiresAt.
// Documents with expiresAt: null are skipped — they live forever.
logEntrySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

logEntrySchema.index({ tenantId: 1, userId: 1, createdAt: -1 });
logEntrySchema.index({ tenantId: 1, action: 1, createdAt: -1 });
logEntrySchema.index({ tenantId: 1, createdAt: -1 });

// ─── Pre-save: compute expiresAt from retentionPolicy ─────────────────────────
const RETENTION_MS = {
  '30d': 30  * 24 * 60 * 60 * 1000,
  '90d': 90  * 24 * 60 * 60 * 1000,
  '1y':  365 * 24 * 60 * 60 * 1000,
};

logEntrySchema.pre('save', function (next) {
  // Only compute once; if retentionPolicy changes later, recalculate.
  if (!this.expiresAt && this.retentionPolicy !== 'forever') {
    const ms = RETENTION_MS[this.retentionPolicy];
    if (ms) this.expiresAt = new Date(Date.now() + ms);
  }
  next();
});

logEntrySchema.methods.getSummary = function () {
  return `[${this.createdAt.toISOString()}] ${this.role.toUpperCase()} (${this.userId || 'SYSTEM'}) performed ${this.action} on ${this.entity || 'N/A'}`;
};

module.exports = mongoose.model('LogEntry', logEntrySchema);
