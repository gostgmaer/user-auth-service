// src/models/Permission.js
const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema(
  {
    tenantId: { type: String, required: true, index: true },
    name: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    category: { type: String, required: true },
    key: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
    },
    resource: { type: String, required: true, trim: true, lowercase: true },
    action: {
      type: String,
      required: true,
      enum: ['create', 'write', 'read', 'update', 'delete', 'view', 'manage', 'approve', 'reject', 'publish', 'archive', 'export', 'import'],
    },
    isDefault: { type: Boolean, default: false },
    isActive:  { type: Boolean, default: true },
    isDeleted: { type: Boolean, default: false },
    created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    updated_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    deleted_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    deletedAt:  { type: Date, default: null },
  },
  { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
);

permissionSchema.index({ tenantId: 1, key: 1 }, { unique: true });
permissionSchema.index({ tenantId: 1, resource: 1 });
permissionSchema.index({ tenantId: 1, isActive: 1 });

permissionSchema.pre('validate', function (next) {
  if (!this.key && this.action && this.resource) {
    this.key = `${this.action.trim().toLowerCase()}:${this.resource.trim().toLowerCase()}`;
  }
  next();
});

permissionSchema.statics.getActivePermissions = function (tenantId) {
  return this.find({ tenantId, isActive: true, isDeleted: false })
    .populate('created_by updated_by', 'firstName lastName username email')
    .sort({ category: 1, name: 1 });
};

/**
 * Resolve a user reference to the best available display label.
 * Priority: "First Last" → username → email → id string
 */
function resolveUserRef(ref) {
  if (!ref) return null;
  if (ref !== null && typeof ref === 'object' && !ref._bsontype) {
    const fullName = [ref.firstName, ref.lastName].filter(Boolean).join(' ').trim();
    if (fullName) return fullName;
    if (ref.username) return ref.username;
    if (ref.email)    return ref.email;
    return String(ref._id ?? ref.id);
  }
  return String(ref);
}

permissionSchema.methods.toAPIResponse = function () {
  return {
    id:          this._id,
    name:        this.name,
    description: this.description,
    category:    this.category,
    key:         this.key,
    resource:    this.resource,
    action:      this.action,
    isDefault:   this.isDefault,
    isActive:    this.isActive,
    createdAt:   this.createdAt,
    updatedAt:   this.updatedAt,
    createdBy:   resolveUserRef(this.created_by),
    updatedBy:   resolveUserRef(this.updated_by),
    deletedBy:   resolveUserRef(this.deleted_by),
  };
};

module.exports = mongoose.model('Permission', permissionSchema);
