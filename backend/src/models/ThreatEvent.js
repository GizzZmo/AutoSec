const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

// Threat Detection Events Schema
const threatEventSchema = new mongoose.Schema({
  eventId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  eventType: {
    type: String,
    enum: [
      'anomaly_detection',
      'behavioral_deviation',
      'threat_intelligence_match',
      'ml_prediction',
      'rule_violation',
      'correlation_match',
      'manual_investigation'
    ],
    required: true,
  },
  severity: {
    type: String,
    enum: ['info', 'low', 'medium', 'high', 'critical'],
    required: true,
  },
  title: {
    type: String,
    required: true,
    maxlength: 200,
  },
  description: {
    type: String,
    required: true,
    maxlength: 1000,
  },
  source: {
    system: {
      type: String,
      enum: ['ueba', 'nba', 'threat_intel', 'ml_engine', 'rule_engine', 'correlation_engine'],
      required: true,
    },
    detector: String,
    version: String,
  },
  entities: {
    users: [{
      userId: String,
      username: String,
      role: String,
    }],
    devices: [{
      deviceId: String,
      deviceName: String,
      ipAddress: String,
      macAddress: String,
    }],
    networks: [{
      ipAddress: String,
      subnet: String,
      asn: String,
      organization: String,
    }],
    files: [{
      fileName: String,
      filePath: String,
      fileHash: String,
      fileSize: Number,
    }],
  },
  evidence: {
    logs: [String], // References to log entries
    patterns: [{
      type: String,
      value: String,
      confidence: { type: Number, min: 0, max: 1 },
    }],
    indicators: [{
      type: String, // IOC type (ip, domain, hash, etc.)
      value: String,
      source: String,
      confidence: { type: Number, min: 0, max: 1 },
    }],
    behavior: {
      baseline: mongoose.Schema.Types.Mixed,
      observed: mongoose.Schema.Types.Mixed,
      deviation: { type: Number, min: 0, max: 100 },
    },
    mlScores: [{
      model: String,
      score: { type: Number, min: 0, max: 1 },
      confidence: { type: Number, min: 0, max: 1 },
      features: mongoose.Schema.Types.Mixed,
    }],
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true,
  },
  falsePositiveRisk: {
    type: Number,
    min: 0,
    max: 1,
    default: 0,
  },
  status: {
    type: String,
    enum: ['new', 'investigating', 'confirmed', 'false_positive', 'resolved', 'suppressed'],
    default: 'new',
  },
  assignedTo: {
    userId: String,
    username: String,
    assignedAt: { type: Date },
  },
  timeline: [{
    timestamp: { type: Date, default: Date.now },
    action: String,
    userId: String,
    username: String,
    description: String,
  }],
  mitigationActions: [{
    action: {
      type: String,
      enum: ['block_ip', 'disable_user', 'isolate_device', 'quarantine_file', 'alert_admin', 'custom'],
    },
    status: {
      type: String,
      enum: ['pending', 'in_progress', 'completed', 'failed'],
    },
    executedAt: Date,
    executedBy: String,
    details: mongoose.Schema.Types.Mixed,
  }],
  correlatedEvents: [{
    eventId: String,
    correlation: String,
    strength: { type: Number, min: 0, max: 1 },
  }],
  tags: [String],
  metadata: {
    ttl: { type: Date }, // Time to live for automatic cleanup
    retention: { type: Number, default: 90 }, // Days to retain
    compliance: [String], // Compliance frameworks this relates to
    customFields: mongoose.Schema.Types.Mixed,
  },
  acknowledged: {
    by: String,
    at: Date,
    comment: String,
  },
  resolved: {
    by: String,
    at: Date,
    resolution: String,
    comment: String,
  },
}, {
  timestamps: true,
});

// Indexes for better performance
threatEventSchema.index({ eventType: 1, severity: 1 });
threatEventSchema.index({ status: 1, createdAt: -1 });
threatEventSchema.index({ riskScore: -1 });
threatEventSchema.index({ 'source.system': 1 });
threatEventSchema.index({ 'entities.users.userId': 1 });
threatEventSchema.index({ 'entities.devices.ipAddress': 1 });
threatEventSchema.index({ tags: 1 });
threatEventSchema.index({ createdAt: -1 });
threatEventSchema.index({ 'metadata.ttl': 1 }, { expireAfterSeconds: 0 });

// Text index for search
threatEventSchema.index({ 
  title: 'text', 
  description: 'text', 
  tags: 'text' 
});

// Add pagination plugin
threatEventSchema.plugin(mongoosePaginate);

const ThreatEvent = mongoose.model('ThreatEvent', threatEventSchema);

module.exports = ThreatEvent;