// src/models/Role.js
const mongoose = require('mongoose');

const PREDEFINED_ROLES = [
  'super_admin', 'admin', 'manager', 'staff', 'vendor',
  'customer', 'guest', 'support_agent', 'moderator', 'user',
];

const roleSchema = new mongoose.Schema(
  {
    tenantId:    { type: String, required: true, index: true },
    name: {
      type: String,
      enum: PREDEFINED_ROLES,
      required: true,
      trim: true,
    },
    description: { type: String, trim: true },
    permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }],
    isDefault:   { type: Boolean, default: false },
    isDeleted:   { type: Boolean, default: false },
    isActive:    { type: Boolean, default: true },
    created_by:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    updated_by:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    deleted_by:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    deletedAt:   { type: Date, default: null },
  },
  { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
);

roleSchema.index({ tenantId: 1, name: 1 }, { unique: true });
roleSchema.index({ tenantId: 1, isActive: 1 });

roleSchema.methods.toAPIResponse = function () {
  return {
    id: this._id,
    name: this.name,
    description: this.description,
    permissions: this.permissions,
    isDefault: this.isDefault,
    isActive: this.isActive,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
    createdBy: this.created_by,
    updatedBy: this.updated_by,
  };
};

roleSchema.statics.getActiveRoles = function (tenantId) {
  return this.find({ tenantId, isActive: true, isDeleted: false }).sort({ name: 1 });
};

roleSchema.statics.getDefaultRole = function (tenantId) {
  return this.findOne({ tenantId, isDefault: true, isDeleted: false });
};

module.exports = mongoose.model('Role', roleSchema);
module.exports.PREDEFINED_ROLES = PREDEFINED_ROLES;
