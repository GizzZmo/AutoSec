/**
 * Report Model
 * Represents generated reports with metadata and content
 */

const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: [
      'security_summary',
      'executive_dashboard', 
      'compliance_audit',
      'threat_intelligence',
      'incident_response',
      'ml_performance',
      'network_analysis',
      'user_behavior'
    ],
    index: true
  },
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  description: {
    type: String,
    maxlength: 1000
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  parameters: {
    timeRange: String,
    format: {
      type: String,
      enum: ['pdf', 'excel', 'json', 'csv'],
      default: 'pdf'
    },
    includeCharts: { type: Boolean, default: true },
    includeKPIs: { type: Boolean, default: true },
    frameworks: [String],
    severity: [String],
    models: [String],
    delivery: {
      method: {
        type: String,
        enum: ['email', 'webhook', 'storage', 'none'],
        default: 'none'
      },
      recipients: [String],
      webhook: String,
      storageLocation: String
    }
  },
  status: {
    type: String,
    enum: ['pending', 'generating', 'completed', 'failed', 'cancelled'],
    default: 'pending',
    index: true
  },
  content: {
    sections: [{
      title: String,
      content: mongoose.Schema.Types.Mixed,
      type: {
        type: String,
        enum: ['text', 'table', 'chart', 'image', 'raw'],
        default: 'text'
      },
      chartType: String,
      headers: [String]
    }],
    metadata: {
      generatedAt: Date,
      dataPoints: Number,
      coverage: String,
      executionTime: Number,
      fileSize: Number,
      checksum: String
    }
  },
  filePath: String,
  downloadCount: {
    type: Number,
    default: 0
  },
  error: String,
  metadata: {
    generatedAt: {
      type: Date,
      default: Date.now
    },
    dataPoints: {
      type: Number,
      default: 0
    },
    executionTime: {
      type: Number,
      default: 0
    },
    fileSize: Number,
    version: {
      type: Number,
      default: 1
    }
  },
  permissions: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    level: {
      type: String,
      enum: ['read', 'download'],
      default: 'read'
    },
    grantedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    grantedAt: {
      type: Date,
      default: Date.now
    }
  }],
  tags: [{
    type: String,
    trim: true,
    maxlength: 50
  }],
  isArchived: {
    type: Boolean,
    default: false
  },
  expiresAt: Date
}, {
  timestamps: true
});

// Indexes
reportSchema.index({ userId: 1, type: 1 });
reportSchema.index({ status: 1, createdAt: -1 });
reportSchema.index({ 'metadata.generatedAt': -1 });
reportSchema.index({ tags: 1 });
reportSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Virtual for content size
reportSchema.virtual('contentSize').get(function() {
  if (this.content && this.content.sections) {
    return JSON.stringify(this.content).length;
  }
  return 0;
});

// Instance methods
reportSchema.methods.incrementDownloadCount = function() {
  this.downloadCount = (this.downloadCount || 0) + 1;
  return this.save();
};

reportSchema.methods.hasAccess = function(userId, level = 'read') {
  // Owner has full access
  if (this.userId.toString() === userId.toString()) {
    return true;
  }

  // Check explicit permissions
  const permission = this.permissions.find(p => 
    p.userId.toString() === userId.toString()
  );

  if (!permission) {
    return false;
  }

  const levelHierarchy = { 'read': 0, 'download': 1 };
  return levelHierarchy[permission.level] >= levelHierarchy[level];
};

reportSchema.methods.grantAccess = function(userId, level, grantedBy) {
  // Remove existing permission for this user
  this.permissions = this.permissions.filter(p => 
    p.userId.toString() !== userId.toString()
  );

  // Add new permission
  this.permissions.push({
    userId,
    level,
    grantedBy,
    grantedAt: new Date()
  });

  return this.save();
};

reportSchema.methods.revokeAccess = function(userId) {
  this.permissions = this.permissions.filter(p => 
    p.userId.toString() !== userId.toString()
  );
  return this.save();
};

reportSchema.methods.toSafeObject = function() {
  const obj = this.toObject();
  
  // Remove large content for list views
  if (obj.content && obj.content.sections && obj.content.sections.length > 0) {
    obj.content.summary = `${obj.content.sections.length} sections`;
    delete obj.content.sections;
  }
  
  return obj;
};

// Static methods
reportSchema.statics.findByUser = function(userId, options = {}) {
  const query = { 
    $or: [
      { userId },
      { 'permissions.userId': userId }
    ]
  };
  
  if (options.type) {
    query.type = options.type;
  }
  
  if (options.status) {
    query.status = options.status;
  }

  if (!options.includeArchived) {
    query.isArchived = { $ne: true };
  }

  return this.find(query)
    .populate('userId', 'username email')
    .sort({ createdAt: -1 })
    .limit(options.limit || 50);
};

reportSchema.statics.findExpired = function() {
  return this.find({
    expiresAt: { $lt: new Date() },
    isArchived: false
  });
};

reportSchema.statics.getStatistics = function(userId) {
  return this.aggregate([
    { $match: { userId: mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: null,
        totalReports: { $sum: 1 },
        completedReports: {
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        },
        failedReports: {
          $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
        },
        totalDownloads: { $sum: '$downloadCount' },
        avgExecutionTime: { $avg: '$metadata.executionTime' },
        totalDataPoints: { $sum: '$metadata.dataPoints' },
        reportsByType: {
          $push: {
            type: '$type',
            count: 1
          }
        }
      }
    }
  ]);
};

// Pre-save middleware
reportSchema.pre('save', function(next) {
  // Set expiration for completed reports (default 90 days)
  if (this.status === 'completed' && !this.expiresAt) {
    this.expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
  }

  next();
});

// Post-save middleware
reportSchema.post('save', function(doc) {
  // Log report generation completion
  if (doc.status === 'completed') {
    const logger = require('../config/logger');
    logger.info(`Report completed: ${doc._id} (${doc.type}) for user ${doc.userId}`);
  }
});

const Report = mongoose.model('Report', reportSchema);
module.exports = Report;