/**
 * Incident Model
 * Represents security incidents and their lifecycle
 */

const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

// Incident Schema
const incidentSchema = new mongoose.Schema({
  incidentId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  title: {
    type: String,
    required: true,
    maxlength: 200,
  },
  description: {
    type: String,
    required: true,
    maxlength: 2000,
  },
  severity: {
    type: String,
    enum: ['info', 'low', 'medium', 'high', 'critical'],
    required: true,
    index: true,
  },
  status: {
    type: String,
    enum: ['new', 'investigating', 'in_progress', 'contained', 'eradicated', 'recovering', 'closed', 'resolved'],
    default: 'new',
    index: true,
  },
  category: {
    type: String,
    enum: ['malware', 'phishing', 'data_breach', 'insider_threat', 'ddos', 'unauthorized_access', 'policy_violation', 'suspicious_activity', 'advanced_threat', 'other'],
    required: true,
    index: true,
  },
  priority: {
    type: String,
    enum: ['p1', 'p2', 'p3', 'p4', 'p5'],
    default: 'p3',
  },
  source: {
    eventId: String,
    system: String,
    detector: String,
    reportedBy: String,
  },
  assignedTo: {
    assignee: String,
    assignedAt: Date,
    assignedBy: String,
    reason: String,
  },
  escalationLevel: {
    type: Number,
    default: 0,
    min: 0,
    max: 5,
  },
  entities: {
    users: [{
      userId: String,
      username: String,
      role: String,
      affected: { type: Boolean, default: false },
    }],
    devices: [{
      deviceId: String,
      deviceName: String,
      ipAddress: String,
      macAddress: String,
      affected: { type: Boolean, default: false },
    }],
    networks: [{
      ipAddress: String,
      subnet: String,
      asn: String,
      organization: String,
      affected: { type: Boolean, default: false },
    }],
    files: [{
      fileName: String,
      filePath: String,
      fileHash: String,
      fileSize: Number,
      affected: { type: Boolean, default: false },
    }],
    applications: [{
      appName: String,
      version: String,
      vendor: String,
      affected: { type: Boolean, default: false },
    }],
  },
  evidence: {
    logs: [String],
    artifacts: [{
      type: String,
      name: String,
      path: String,
      hash: String,
      collectedAt: { type: Date, default: Date.now },
      collectedBy: String,
    }],
    screenshots: [{
      name: String,
      path: String,
      takenAt: { type: Date, default: Date.now },
      takenBy: String,
    }],
    networkCaptures: [{
      name: String,
      path: String,
      capturedAt: { type: Date, default: Date.now },
      capturedBy: String,
    }],
    indicators: [{
      type: String,
      value: String,
      source: String,
      confidence: { type: Number, min: 0, max: 1 },
    }],
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true,
  },
  containmentStatus: {
    type: String,
    enum: ['not_started', 'in_progress', 'partial', 'complete'],
    default: 'not_started',
  },
  containmentActions: [{
    action: String,
    status: {
      type: String,
      enum: ['pending', 'in_progress', 'completed', 'failed'],
    },
    executedAt: Date,
    executedBy: String,
    result: String,
    details: mongoose.Schema.Types.Mixed,
  }],
  timeline: [{
    timestamp: { type: Date, default: Date.now },
    action: String,
    description: String,
    userId: String,
    username: String,
    automated: { type: Boolean, default: false },
    details: mongoose.Schema.Types.Mixed,
  }],
  communications: [{
    timestamp: { type: Date, default: Date.now },
    type: {
      type: String,
      enum: ['email', 'phone', 'chat', 'meeting', 'notification'],
    },
    from: String,
    to: [String],
    subject: String,
    message: String,
    attachments: [String],
  }],
  playbooks: [{
    playbookId: String,
    playbookName: String,
    executionId: String,
    status: {
      type: String,
      enum: ['pending', 'running', 'completed', 'failed', 'cancelled'],
    },
    startedAt: Date,
    completedAt: Date,
    executedBy: String,
    automated: { type: Boolean, default: false },
    results: mongoose.Schema.Types.Mixed,
  }],
  externalTickets: [{
    system: String,
    ticketId: String,
    ticketUrl: String,
    status: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: Date,
    syncStatus: {
      type: String,
      enum: ['synced', 'out_of_sync', 'error'],
      default: 'synced',
    },
  }],
  compliance: {
    regulations: [String], // GDPR, HIPAA, SOX, etc.
    reportingRequired: { type: Boolean, default: false },
    reportingDeadline: Date,
    reportedAt: Date,
    reportedBy: String,
    breachNotification: {
      required: { type: Boolean, default: false },
      deadline: Date,
      notifiedAt: Date,
      authorities: [String],
      customers: { type: Boolean, default: false },
    },
  },
  financialImpact: {
    estimatedLoss: Number,
    recoveryCoast: Number,
    currency: { type: String, default: 'USD' },
    businessImpact: {
      type: String,
      enum: ['none', 'minimal', 'moderate', 'significant', 'severe'],
    },
  },
  resolution: {
    status: String,
    resolvedAt: Date,
    resolvedBy: String,
    summary: String,
    rootCause: String,
    lessonsLearned: String,
    preventiveMeasures: [String],
    followUpActions: [{
      action: String,
      assignee: String,
      dueDate: Date,
      status: String,
    }],
  },
  tags: [{
    type: String,
    index: true,
  }],
  notes: [{
    timestamp: { type: Date, default: Date.now },
    author: String,
    note: String,
    private: { type: Boolean, default: false },
    category: {
      type: String,
      enum: ['investigation', 'containment', 'analysis', 'communication', 'other'],
    },
  }],
  attachments: [{
    name: String,
    path: String,
    type: String,
    size: Number,
    uploadedAt: { type: Date, default: Date.now },
    uploadedBy: String,
  }],
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better query performance
incidentSchema.index({ status: 1, severity: 1 });
incidentSchema.index({ category: 1, createdAt: -1 });
incidentSchema.index({ 'assignedTo.assignee': 1, status: 1 });
incidentSchema.index({ escalationLevel: 1, createdAt: -1 });
incidentSchema.index({ riskScore: -1 });
incidentSchema.index({ tags: 1 });

// Text index for searching
incidentSchema.index({
  title: 'text',
  description: 'text',
  'notes.note': 'text',
  'resolution.summary': 'text'
});

// Virtual for incident age
incidentSchema.virtual('age').get(function() {
  return Date.now() - this.createdAt.getTime();
});

// Virtual for time to resolution
incidentSchema.virtual('timeToResolution').get(function() {
  if (this.resolution && this.resolution.resolvedAt) {
    return this.resolution.resolvedAt.getTime() - this.createdAt.getTime();
  }
  return null;
});

// Virtual for current phase duration
incidentSchema.virtual('currentPhaseDuration').get(function() {
  const lastStatusChange = this.timeline
    .filter(t => t.action === 'status_changed')
    .sort((a, b) => b.timestamp - a.timestamp)[0];
  
  const startTime = lastStatusChange ? lastStatusChange.timestamp : this.createdAt;
  return Date.now() - startTime.getTime();
});

// Virtual for overdue status
incidentSchema.virtual('isOverdue').get(function() {
  if (this.status === 'closed' || this.status === 'resolved') {
    return false;
  }

  const slaThresholds = {
    'critical': 4 * 60 * 60 * 1000, // 4 hours
    'high': 24 * 60 * 60 * 1000,   // 24 hours
    'medium': 72 * 60 * 60 * 1000, // 72 hours
    'low': 168 * 60 * 60 * 1000,   // 168 hours (1 week)
  };

  const threshold = slaThresholds[this.severity] || slaThresholds.medium;
  return this.age > threshold;
});

// Pre-save middleware
incidentSchema.pre('save', function(next) {
  // Auto-calculate priority based on severity and risk score if not set
  if (this.isNew && !this.priority) {
    if (this.severity === 'critical' || this.riskScore >= 90) {
      this.priority = 'p1';
    } else if (this.severity === 'high' || this.riskScore >= 70) {
      this.priority = 'p2';
    } else if (this.severity === 'medium' || this.riskScore >= 50) {
      this.priority = 'p3';
    } else if (this.severity === 'low' || this.riskScore >= 30) {
      this.priority = 'p4';
    } else {
      this.priority = 'p5';
    }
  }

  next();
});

// Instance methods
incidentSchema.methods.addTimelineEntry = function(action, description, userId, details = {}) {
  this.timeline.push({
    timestamp: new Date(),
    action,
    description,
    userId,
    username: details.username,
    automated: details.automated || false,
    details,
  });
  return this.save();
};

incidentSchema.methods.addNote = function(note, author, category = 'investigation', isPrivate = false) {
  this.notes.push({
    timestamp: new Date(),
    author,
    note,
    private: isPrivate,
    category,
  });
  return this.save();
};

incidentSchema.methods.addEvidence = function(evidence, collectedBy) {
  if (evidence.type === 'log') {
    this.evidence.logs.push(evidence.value);
  } else if (evidence.type === 'artifact') {
    this.evidence.artifacts.push({
      ...evidence,
      collectedAt: new Date(),
      collectedBy,
    });
  } else if (evidence.type === 'indicator') {
    this.evidence.indicators.push(evidence);
  }
  
  return this.save();
};

incidentSchema.methods.executeContainmentAction = function(action, executedBy) {
  this.containmentActions.push({
    action: action.name,
    status: 'pending',
    executedAt: new Date(),
    executedBy,
    details: action.details,
  });

  // Update overall containment status
  if (this.containmentStatus === 'not_started') {
    this.containmentStatus = 'in_progress';
  }

  return this.save();
};

incidentSchema.methods.updateContainmentActionStatus = function(actionIndex, status, result = null) {
  if (this.containmentActions[actionIndex]) {
    this.containmentActions[actionIndex].status = status;
    if (result) {
      this.containmentActions[actionIndex].result = result;
    }

    // Update overall containment status
    const allActions = this.containmentActions;
    const completedActions = allActions.filter(a => a.status === 'completed');
    const failedActions = allActions.filter(a => a.status === 'failed');

    if (completedActions.length === allActions.length) {
      this.containmentStatus = 'complete';
    } else if (completedActions.length > 0) {
      this.containmentStatus = 'partial';
    }
  }

  return this.save();
};

incidentSchema.methods.escalate = function(reason, escalatedBy) {
  this.escalationLevel += 1;
  this.addTimelineEntry(
    'incident_escalated',
    `Incident escalated to level ${this.escalationLevel}: ${reason}`,
    escalatedBy,
    { reason, escalationLevel: this.escalationLevel }
  );
  
  return this.save();
};

incidentSchema.methods.close = function(summary, resolvedBy, rootCause = null) {
  this.status = 'closed';
  this.resolution = {
    status: 'closed',
    resolvedAt: new Date(),
    resolvedBy,
    summary,
    rootCause,
  };

  this.addTimelineEntry(
    'incident_closed',
    'Incident closed',
    resolvedBy,
    { summary, rootCause }
  );

  return this.save();
};

// Static methods
incidentSchema.statics.findActive = function() {
  return this.find({
    status: { $nin: ['closed', 'resolved'] }
  });
};

incidentSchema.statics.findOverdue = function() {
  const now = new Date();
  const fourHoursAgo = new Date(now.getTime() - 4 * 60 * 60 * 1000);
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const threeDaysAgo = new Date(now.getTime() - 72 * 60 * 60 * 1000);
  const oneWeekAgo = new Date(now.getTime() - 168 * 60 * 60 * 1000);

  return this.find({
    status: { $nin: ['closed', 'resolved'] },
    $or: [
      { severity: 'critical', createdAt: { $lt: fourHoursAgo } },
      { severity: 'high', createdAt: { $lt: oneDayAgo } },
      { severity: 'medium', createdAt: { $lt: threeDaysAgo } },
      { severity: 'low', createdAt: { $lt: oneWeekAgo } },
    ]
  });
};

incidentSchema.statics.getStatistics = function(timeframe = '30d') {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - parseInt(timeframe));

  return this.aggregate([
    { $match: { createdAt: { $gte: startDate } } },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        bySeverity: {
          $push: {
            severity: '$severity',
            count: 1
          }
        },
        byStatus: {
          $push: {
            status: '$status',
            count: 1
          }
        },
        byCategory: {
          $push: {
            category: '$category',
            count: 1
          }
        },
        avgRiskScore: { $avg: '$riskScore' },
        avgTimeToResolution: {
          $avg: {
            $cond: [
              { $ne: ['$resolution.resolvedAt', null] },
              { $subtract: ['$resolution.resolvedAt', '$createdAt'] },
              null
            ]
          }
        }
      }
    }
  ]);
};

// Apply pagination plugin
incidentSchema.plugin(mongoosePaginate);

const Incident = mongoose.model('Incident', incidentSchema);

module.exports = Incident;