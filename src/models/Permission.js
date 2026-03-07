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
  return this.find({ tenantId, isActive: true, isDeleted: false }).sort({ category: 1, name: 1 });
};

module.exports = mongoose.model('Permission', permissionSchema);
