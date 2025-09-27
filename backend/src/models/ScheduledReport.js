/**
 * Scheduled Report Model
 * Represents scheduled report generation tasks
 */

const mongoose = require('mongoose');

const scheduledReportSchema = new mongoose.Schema({
  scheduleId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
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
    ]
  },
  title: {
    type: String,
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
    models: [String]
  },
  schedule: {
    cron: {
      type: String,
      required: true
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    enabled: {
      type: Boolean,
      default: true
    },
    startDate: Date,
    endDate: Date
  },
  delivery: {
    method: {
      type: String,
      enum: ['email', 'webhook', 'storage', 'none'],
      default: 'email'
    },
    recipients: [String],
    webhook: {
      url: String,
      headers: mongoose.Schema.Types.Mixed,
      method: {
        type: String,
        enum: ['POST', 'PUT'],
        default: 'POST'
      }
    },
    email: {
      subject: String,
      body: String,
      attachReport: {
        type: Boolean,
        default: true
      }
    },
    storage: {
      type: {
        type: String,
        enum: ['s3', 'local', 'azure', 'gcs']
      },
      bucket: String,
      path: String,
      credentials: mongoose.Schema.Types.Mixed
    }
  },
  metadata: {
    createdAt: {
      type: Date,
      default: Date.now
    },
    lastRun: Date,
    nextRun: Date,
    runCount: {
      type: Number,
      default: 0
    },
    successCount: {
      type: Number,
      default: 0
    },
    errorCount: {
      type: Number,
      default: 0
    },
    lastError: String,
    avgExecutionTime: Number,
    totalDataPoints: Number
  },
  status: {
    type: String,
    enum: ['active', 'paused', 'disabled', 'expired'],
    default: 'active',
    index: true
  },
  tags: [{
    type: String,
    trim: true,
    maxlength: 50
  }],
  notifications: {
    onSuccess: {
      type: Boolean,
      default: false
    },
    onFailure: {
      type: Boolean,
      default: true
    },
    recipients: [String]
  }
}, {
  timestamps: true
});

// Indexes
scheduledReportSchema.index({ userId: 1, type: 1 });
scheduledReportSchema.index({ 'schedule.enabled': 1, status: 1 });
scheduledReportSchema.index({ 'metadata.nextRun': 1 });
scheduledReportSchema.index({ tags: 1 });

// Virtual for schedule description
scheduledReportSchema.virtual('scheduleDescription').get(function() {
  // Convert cron to human readable format
  const cronParts = this.schedule.cron.split(' ');
  if (cronParts.length === 5) {
    const [minute, hour, day, month, weekday] = cronParts;
    
    if (minute === '0' && hour === '0' && day === '*' && month === '*' && weekday === '*') {
      return 'Daily at midnight';
    } else if (minute === '0' && hour === '0' && day === '*' && month === '*' && weekday === '1') {
      return 'Weekly on Monday';
    } else if (minute === '0' && hour === '0' && day === '1' && month === '*' && weekday === '*') {
      return 'Monthly on the 1st';
    }
  }
  
  return this.schedule.cron;
});

// Virtual for success rate
scheduledReportSchema.virtual('successRate').get(function() {
  if (this.metadata.runCount === 0) return 0;
  return (this.metadata.successCount / this.metadata.runCount) * 100;
});

// Instance methods
scheduledReportSchema.methods.updateRunStatistics = function(success, executionTime, dataPoints, error = null) {
  this.metadata.lastRun = new Date();
  this.metadata.runCount = (this.metadata.runCount || 0) + 1;
  
  if (success) {
    this.metadata.successCount = (this.metadata.successCount || 0) + 1;
    this.metadata.lastError = null;
  } else {
    this.metadata.errorCount = (this.metadata.errorCount || 0) + 1;
    this.metadata.lastError = error;
  }

  if (executionTime) {
    const totalExecTime = (this.metadata.avgExecutionTime || 0) * (this.metadata.runCount - 1);
    this.metadata.avgExecutionTime = (totalExecTime + executionTime) / this.metadata.runCount;
  }

  if (dataPoints) {
    this.metadata.totalDataPoints = (this.metadata.totalDataPoints || 0) + dataPoints;
  }

  return this.save();
};

scheduledReportSchema.methods.enable = function() {
  this.schedule.enabled = true;
  this.status = 'active';
  return this.save();
};

scheduledReportSchema.methods.disable = function() {
  this.schedule.enabled = false;
  this.status = 'disabled';
  return this.save();
};

scheduledReportSchema.methods.pause = function() {
  this.schedule.enabled = false;
  this.status = 'paused';
  return this.save();
};

scheduledReportSchema.methods.resume = function() {
  this.schedule.enabled = true;
  this.status = 'active';
  return this.save();
};

scheduledReportSchema.methods.isExpired = function() {
  if (!this.schedule.endDate) return false;
  return new Date() > this.schedule.endDate;
};

scheduledReportSchema.methods.shouldRun = function() {
  if (!this.schedule.enabled || this.status !== 'active') return false;
  if (this.isExpired()) return false;
  if (this.schedule.startDate && new Date() < this.schedule.startDate) return false;
  return true;
};

// Static methods
scheduledReportSchema.statics.findByUser = function(userId, options = {}) {
  const query = { userId };
  
  if (options.type) {
    query.type = options.type;
  }
  
  if (options.status) {
    query.status = options.status;
  }

  if (options.enabled !== undefined) {
    query['schedule.enabled'] = options.enabled;
  }

  return this.find(query)
    .populate('userId', 'username email')
    .sort({ createdAt: -1 });
};

scheduledReportSchema.statics.findActive = function() {
  return this.find({
    'schedule.enabled': true,
    status: 'active',
    $or: [
      { 'schedule.endDate': { $exists: false } },
      { 'schedule.endDate': { $gt: new Date() } }
    ]
  });
};

scheduledReportSchema.statics.findDue = function() {
  return this.find({
    'schedule.enabled': true,
    status: 'active',
    'metadata.nextRun': { $lte: new Date() }
  });
};

scheduledReportSchema.statics.getStatistics = function(userId) {
  return this.aggregate([
    { $match: { userId: mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: null,
        totalSchedules: { $sum: 1 },
        activeSchedules: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        pausedSchedules: {
          $sum: { $cond: [{ $eq: ['$status', 'paused'] }, 1, 0] }
        },
        totalRuns: { $sum: '$metadata.runCount' },
        totalSuccesses: { $sum: '$metadata.successCount' },
        totalErrors: { $sum: '$metadata.errorCount' },
        avgExecutionTime: { $avg: '$metadata.avgExecutionTime' },
        schedulesByType: {
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
scheduledReportSchema.pre('save', function(next) {
  // Auto-generate title if not provided
  if (!this.title) {
    const reportTypes = {
      'security_summary': 'Security Summary',
      'executive_dashboard': 'Executive Dashboard',
      'compliance_audit': 'Compliance Audit',
      'threat_intelligence': 'Threat Intelligence',
      'incident_response': 'Incident Response',
      'ml_performance': 'ML Performance',
      'network_analysis': 'Network Analysis',
      'user_behavior': 'User Behavior'
    };
    
    const typeName = reportTypes[this.type] || this.type;
    this.title = `${typeName} - ${this.scheduleDescription}`;
  }

  // Update status based on end date
  if (this.schedule.endDate && new Date() > this.schedule.endDate) {
    this.status = 'expired';
    this.schedule.enabled = false;
  }

  next();
});

const ScheduledReport = mongoose.model('ScheduledReport', scheduledReportSchema);
module.exports = ScheduledReport;