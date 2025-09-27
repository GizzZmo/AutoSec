/**
 * Dashboard Model
 * Represents customizable dashboards for analytics and reporting
 */

const mongoose = require('mongoose');

const widgetSchema = new mongoose.Schema({
  id: {
    type: String,
    required: true
  },
  type: {
    type: String,
    required: true,
    enum: [
      'threat_summary',
      'geographic_threats', 
      'recent_events',
      'network_topology',
      'ml_model_performance',
      'executive_summary',
      'real_time_alerts',
      'compliance_status',
      'threat_intelligence',
      'network_traffic_3d'
    ]
  },
  position: {
    x: { type: Number, required: true, min: 0 },
    y: { type: Number, required: true, min: 0 },
    w: { type: Number, required: true, min: 1, max: 12 },
    h: { type: Number, required: true, min: 1, max: 12 }
  },
  config: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  title: String,
  description: String
});

const dashboardSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    maxlength: 500
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  widgets: [widgetSchema],
  layout: {
    type: String,
    enum: ['grid', 'flex', 'fixed'],
    default: 'grid'
  },
  theme: {
    type: String,
    enum: ['light', 'dark', 'auto'],
    default: 'dark'
  },
  autoRefresh: {
    type: Number,
    min: 5,
    max: 300,
    default: 30
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  isDefault: {
    type: Boolean,
    default: false
  },
  tags: [{
    type: String,
    trim: true,
    maxlength: 50
  }],
  permissions: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    level: {
      type: String,
      enum: ['read', 'write', 'admin'],
      default: 'read'
    }
  }],
  metadata: {
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    lastModifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    version: {
      type: Number,
      default: 1
    },
    lastModified: {
      type: Date,
      default: Date.now
    },
    viewCount: {
      type: Number,
      default: 0
    },
    lastViewed: Date
  },
  settings: {
    allowExport: {
      type: Boolean,
      default: true
    },
    allowSharing: {
      type: Boolean,
      default: false
    },
    requireAuth: {
      type: Boolean,
      default: true
    }
  }
}, {
  timestamps: true
});

// Indexes
dashboardSchema.index({ userId: 1, name: 1 });
dashboardSchema.index({ isPublic: 1 });
dashboardSchema.index({ tags: 1 });
dashboardSchema.index({ 'metadata.lastModified': -1 });

// Virtual for widget count
dashboardSchema.virtual('widgetCount').get(function() {
  return this.widgets.length;
});

// Instance methods
dashboardSchema.methods.incrementViewCount = function() {
  this.metadata.viewCount = (this.metadata.viewCount || 0) + 1;
  this.metadata.lastViewed = new Date();
  return this.save();
};

dashboardSchema.methods.hasAccess = function(userId, level = 'read') {
  // Owner has full access
  if (this.userId.toString() === userId.toString()) {
    return true;
  }

  // Check if dashboard is public for read access
  if (level === 'read' && this.isPublic) {
    return true;
  }

  // Check explicit permissions
  const permission = this.permissions.find(p => 
    p.userId.toString() === userId.toString()
  );

  if (!permission) {
    return false;
  }

  const levelHierarchy = { 'read': 0, 'write': 1, 'admin': 2 };
  return levelHierarchy[permission.level] >= levelHierarchy[level];
};

dashboardSchema.methods.toSafeObject = function() {
  const obj = this.toObject();
  
  // Remove sensitive fields based on context
  if (!this.isPublic) {
    delete obj.permissions;
  }
  
  return obj;
};

// Static methods
dashboardSchema.statics.findByUser = function(userId, options = {}) {
  const query = { userId };
  
  if (options.includePublic) {
    query = { $or: [{ userId }, { isPublic: true }] };
  }

  return this.find(query)
    .populate('userId', 'username email')
    .sort({ 'metadata.lastModified': -1 });
};

dashboardSchema.statics.findPublic = function(limit = 20) {
  return this.find({ isPublic: true })
    .populate('userId', 'username')
    .select('-permissions')
    .sort({ 'metadata.viewCount': -1 })
    .limit(limit);
};

dashboardSchema.statics.getDefaultDashboard = function(userId) {
  return this.findOne({ userId, isDefault: true })
    .populate('userId', 'username email');
};

// Pre-save middleware
dashboardSchema.pre('save', function(next) {
  // Ensure widget IDs are unique within the dashboard
  const widgetIds = new Set();
  for (const widget of this.widgets) {
    if (!widget.id) {
      widget.id = new mongoose.Types.ObjectId().toString();
    }
    if (widgetIds.has(widget.id)) {
      return next(new Error('Duplicate widget IDs are not allowed'));
    }
    widgetIds.add(widget.id);
  }

  // Update metadata
  if (this.isModified() && !this.isNew) {
    this.metadata.lastModified = new Date();
  }

  next();
});

// Export model
const Dashboard = mongoose.model('Dashboard', dashboardSchema);
module.exports = Dashboard;