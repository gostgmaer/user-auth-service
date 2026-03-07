// src/models/TokenBlacklist.js
const mongoose = require('mongoose');

const TokenBlacklistSchema = new mongoose.Schema(
  {
    jti:      { type: String, required: true, index: true },
    tenantId: { type: String, required: true, index: true },
    userId:   { type: String, required: true },
    reason:   {
      type: String,
      enum: ['logout', 'password_change', 'revoked_all', 'suspicious'],
      default: 'logout',
    },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true }
);

// Auto-delete documents after the token's natural expiry
TokenBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
TokenBlacklistSchema.index({ tenantId: 1, jti: 1 }, { unique: true });

module.exports = mongoose.model('TokenBlacklist', TokenBlacklistSchema);
