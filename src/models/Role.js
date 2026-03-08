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

// ─── Guard: default role can never be deleted ──────────────────────────────────
// Blocks soft-deletes (isDeleted: true) via save() or findOneAndUpdate()
roleSchema.pre('save', function (next) {
  if (this.isDefault && this.isDeleted) {
    return next(new Error('The default role for a tenant cannot be deleted.'));
  }
  next();
});

// Covers Model.findOneAndUpdate / Model.updateOne / Model.updateMany paths
async function blockDefaultRoleDelete(next) {
  const update = this.getUpdate();
  const isMarkingDeleted =
    update?.isDeleted === true ||
    update?.$set?.isDeleted === true;

  if (!isMarkingDeleted) return next();

  const filter = this.getFilter();
  const role = await this.model.findOne(filter).lean();
  if (role?.isDefault) {
    return next(new Error('The default role for a tenant cannot be deleted.'));
  }
  next();
}
roleSchema.pre('findOneAndUpdate', blockDefaultRoleDelete);
roleSchema.pre('updateOne', blockDefaultRoleDelete);
roleSchema.pre('updateMany', blockDefaultRoleDelete);

// Covers hard-delete via deleteOne() / findOneAndDelete()
async function blockDefaultRoleHardDelete(next) {
  const filter = this.getFilter();
  const role = await this.model.findOne(filter).lean();
  if (role?.isDefault) {
    return next(new Error('The default role for a tenant cannot be deleted.'));
  }
  next();
}
roleSchema.pre('deleteOne', blockDefaultRoleHardDelete);
roleSchema.pre('findOneAndDelete', blockDefaultRoleHardDelete);

/**
 * Resolve a user reference to the best available display label.
 * Priority: "First Last" → username → email → id string
 * Handles both a populated User doc and a raw ObjectId (not yet populated).
 */
function resolveUserRef(ref) {
  if (!ref) return null;
  // Populated document — has at least _id plus profile fields
  if (ref !== null && typeof ref === 'object' && !ref._bsontype) {
    const fullName = [ref.firstName, ref.lastName].filter(Boolean).join(' ').trim();
    if (fullName) return fullName;
    if (ref.username) return ref.username;
    if (ref.email)    return ref.email;
    return String(ref._id ?? ref.id);
  }
  // Raw ObjectId — return id string as last resort
  return String(ref);
}

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
    createdBy: resolveUserRef(this.created_by),
    updatedBy: resolveUserRef(this.updated_by),
    deletedBy: resolveUserRef(this.deleted_by),
  };
};

roleSchema.statics.getActiveRoles = function (tenantId) {
  return this.find({ tenantId, isActive: true, isDeleted: false })
    .populate('created_by updated_by', 'firstName lastName username email')
    .sort({ name: 1 });
};

roleSchema.statics.getDefaultRole = function (tenantId) {
  return this.findOne({ tenantId, isDefault: true, isDeleted: false })
    .populate('created_by updated_by', 'firstName lastName username email');
};

module.exports = mongoose.model('Role', roleSchema);
module.exports.PREDEFINED_ROLES = PREDEFINED_ROLES;
