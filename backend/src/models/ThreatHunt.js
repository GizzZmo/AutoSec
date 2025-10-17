/**
 * ThreatHunt Model
 * Represents a threat hunting campaign with queries and findings
 */

const mongoose = require('mongoose');

const threatHuntSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  hypothesis: {
    type: String,
    trim: true
  },
  queries: [{
    name: {
      type: String,
      required: true
    },
    type: {
      type: String,
      enum: ['network', 'behavior', 'ioc', 'threat_event', 'custom'],
      required: true
    },
    pattern: {
      type: String,
      required: true
    },
    timeWindow: {
      type: String,
      default: '24h'
    }
  }],
  template: {
    type: String,
    enum: ['apt-detection', 'data-exfiltration', 'insider-threat', 'ransomware', 'custom'],
    default: 'custom'
  },
  timeRange: {
    type: String,
    default: '24h'
  },
  targets: [{
    type: {
      type: String,
      enum: ['ip', 'network', 'user', 'host', 'domain']
    },
    value: String
  }],
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  status: {
    type: String,
    enum: ['pending', 'running', 'completed', 'failed', 'stopped'],
    default: 'pending'
  },
  startTime: {
    type: Date,
    default: Date.now
  },
  endTime: {
    type: Date
  },
  userId: {
    type: String,
    required: true
  },
  automated: {
    type: Boolean,
    default: false
  },
  findings: [{
    query: String,
    type: String,
    count: Number,
    severity: {
      type: String,
      enum: ['info', 'low', 'medium', 'high', 'critical']
    },
    results: [mongoose.Schema.Types.Mixed],
    error: String,
    timestamp: Date
  }],
  summary: {
    totalFindings: {
      type: Number,
      default: 0
    },
    highSeverity: {
      type: Number,
      default: 0
    },
    mediumSeverity: {
      type: Number,
      default: 0
    },
    lowSeverity: {
      type: Number,
      default: 0
    },
    executionTime: {
      type: Number,
      default: 0
    }
  },
  progress: {
    queriesExecuted: {
      type: Number,
      default: 0
    },
    totalQueries: {
      type: Number,
      default: 0
    },
    percentage: {
      type: Number,
      default: 0
    }
  },
  error: {
    type: String
  },
  metadata: {
    tags: [String],
    notes: String,
    references: [String]
  }
}, {
  timestamps: true
});

// Indexes for performance
threatHuntSchema.index({ userId: 1, status: 1 });
threatHuntSchema.index({ startTime: -1 });
threatHuntSchema.index({ priority: 1, status: 1 });
threatHuntSchema.index({ template: 1 });

const ThreatHunt = mongoose.model('ThreatHunt', threatHuntSchema);

module.exports = ThreatHunt;
