/**
 * IOC (Indicators of Compromise) Model
 * Stores threat intelligence indicators from various sources
 */

const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

// IOC Schema
const iocSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['ip', 'ip-src', 'ip-dst', 'domain', 'hostname', 'url', 'md5', 'sha1', 'sha256', 'email', 'filename'],
    required: true,
    index: true,
  },
  value: {
    type: String,
    required: true,
    index: true,
  },
  source: {
    type: String,
    required: true,
    enum: ['misp', 'taxii', 'otx', 'custom', 'manual', 'internal'],
    index: true,
  },
  confidence: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.5,
    index: true,
  },
  severity: {
    type: String,
    enum: ['info', 'low', 'medium', 'high', 'critical'],
    default: 'medium',
  },
  tags: [{
    type: String,
    index: true,
  }],
  category: {
    type: String,
    enum: ['malware', 'phishing', 'c2', 'botnet', 'exploit', 'suspicious', 'other'],
    default: 'suspicious',
  },
  firstSeen: {
    type: Date,
    required: true,
    index: true,
  },
  lastSeen: {
    type: Date,
    required: true,
    index: true,
  },
  tlp: {
    type: String,
    enum: ['white', 'green', 'amber', 'red'],
    default: 'white',
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'expired', 'false_positive'],
    default: 'active',
    index: true,
  },
  expirationDate: {
    type: Date,
    index: true,
  },
  context: {
    // Source-specific context information
    stixId: String,
    eventId: String,
    pulseInfo: mongoose.Schema.Types.Mixed,
    description: String,
    feedUrl: String,
    pattern: String,
    comment: String,
  },
  references: [{
    url: String,
    description: String,
    source: String,
  }],
  relatedCampaigns: [{
    name: String,
    id: String,
    source: String,
  }],
  mitigations: [{
    action: String,
    description: String,
    automated: Boolean,
  }],
  enrichment: {
    // Additional enrichment data
    geolocation: {
      country: String,
      city: String,
      asn: String,
      organization: String,
    },
    reputation: {
      score: Number,
      source: String,
      lastChecked: Date,
    },
    whois: {
      registrar: String,
      registrationDate: Date,
      expirationDate: Date,
      nameservers: [String],
    },
    dns: {
      aRecords: [String],
      cnames: [String],
      lastResolved: Date,
    },
    sandbox: {
      malicious: Boolean,
      score: Number,
      analysis: mongoose.Schema.Types.Mixed,
      source: String,
    },
  },
  matchHistory: [{
    timestamp: { type: Date, default: Date.now },
    sourceIp: String,
    sourceHost: String,
    matchedBy: String,
    action: String,
    blocked: Boolean,
  }],
  statistics: {
    totalMatches: { type: Number, default: 0 },
    lastMatch: Date,
    matchesThisWeek: { type: Number, default: 0 },
    matchesThisMonth: { type: Number, default: 0 },
    falsePositives: { type: Number, default: 0 },
  },
  notes: [{
    timestamp: { type: Date, default: Date.now },
    analyst: String,
    note: String,
    category: {
      type: String,
      enum: ['analysis', 'false_positive', 'validation', 'context', 'mitigation'],
    },
  }],
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Compound indexes for better query performance
iocSchema.index({ type: 1, value: 1 }, { unique: true });
iocSchema.index({ source: 1, status: 1 });
iocSchema.index({ confidence: -1, severity: 1 });
iocSchema.index({ lastSeen: -1 });
iocSchema.index({ tags: 1, status: 1 });
iocSchema.index({ category: 1, tlp: 1 });

// Text index for searching
iocSchema.index({
  value: 'text',
  tags: 'text',
  'context.description': 'text',
  'context.comment': 'text'
});

// Virtual for age calculation
iocSchema.virtual('age').get(function() {
  return Date.now() - this.firstSeen.getTime();
});

// Virtual for freshness
iocSchema.virtual('freshness').get(function() {
  return Date.now() - this.lastSeen.getTime();
});

// Virtual for effectiveness score
iocSchema.virtual('effectiveness').get(function() {
  if (this.statistics.totalMatches === 0) return 0;
  const falsePositiveRate = this.statistics.falsePositives / this.statistics.totalMatches;
  return Math.max(0, 1 - falsePositiveRate) * this.confidence;
});

// Pre-save middleware
iocSchema.pre('save', function(next) {
  // Update severity based on confidence if not explicitly set
  if (this.isModified('confidence') && !this.isModified('severity')) {
    if (this.confidence >= 0.8) this.severity = 'high';
    else if (this.confidence >= 0.6) this.severity = 'medium';
    else if (this.confidence >= 0.4) this.severity = 'low';
    else this.severity = 'info';
  }

  // Set expiration date if not set (default 30 days for most IOCs)
  if (!this.expirationDate) {
    const expirationDays = this.getExpirationDays();
    this.expirationDate = new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000);
  }

  next();
});

// Instance methods
iocSchema.methods.getExpirationDays = function() {
  const expirationMap = {
    'ip': 30,
    'domain': 60,
    'url': 30,
    'md5': 365,
    'sha1': 365,
    'sha256': 365,
    'email': 90,
    'filename': 180,
  };
  return expirationMap[this.type] || 30;
};

iocSchema.methods.isExpired = function() {
  return this.expirationDate && this.expirationDate < new Date();
};

iocSchema.methods.shouldExpireSoon = function(days = 7) {
  if (!this.expirationDate) return false;
  const warningTime = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  return this.expirationDate < warningTime;
};

iocSchema.methods.recordMatch = function(matchInfo = {}) {
  this.statistics.totalMatches += 1;
  this.statistics.lastMatch = new Date();
  this.lastSeen = new Date();
  
  // Update weekly/monthly counters
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  
  // Simple increment for now (could be more sophisticated with time-based cleanup)
  this.statistics.matchesThisWeek += 1;
  this.statistics.matchesThisMonth += 1;

  // Add to match history
  this.matchHistory.push({
    timestamp: now,
    sourceIp: matchInfo.sourceIp,
    sourceHost: matchInfo.sourceHost,
    matchedBy: matchInfo.matchedBy || 'unknown',
    action: matchInfo.action || 'detected',
    blocked: matchInfo.blocked || false,
  });

  // Keep only last 100 matches in history
  if (this.matchHistory.length > 100) {
    this.matchHistory = this.matchHistory.slice(-100);
  }

  return this.save();
};

iocSchema.methods.markFalsePositive = function(analyst, note) {
  this.statistics.falsePositives += 1;
  this.status = 'false_positive';
  
  this.notes.push({
    analyst,
    note,
    category: 'false_positive',
  });

  return this.save();
};

iocSchema.methods.enrich = function(enrichmentData) {
  if (enrichmentData.geolocation) {
    this.enrichment.geolocation = { ...this.enrichment.geolocation, ...enrichmentData.geolocation };
  }
  if (enrichmentData.reputation) {
    this.enrichment.reputation = enrichmentData.reputation;
  }
  if (enrichmentData.whois) {
    this.enrichment.whois = enrichmentData.whois;
  }
  if (enrichmentData.dns) {
    this.enrichment.dns = enrichmentData.dns;
  }
  if (enrichmentData.sandbox) {
    this.enrichment.sandbox = enrichmentData.sandbox;
  }

  return this.save();
};

// Static methods
iocSchema.statics.findActive = function() {
  return this.find({ 
    status: 'active',
    $or: [
      { expirationDate: { $exists: false } },
      { expirationDate: { $gt: new Date() } }
    ]
  });
};

iocSchema.statics.findByType = function(type) {
  return this.find({ type, status: 'active' });
};

iocSchema.statics.findExpired = function() {
  return this.find({
    expirationDate: { $lt: new Date() },
    status: { $ne: 'expired' }
  });
};

iocSchema.statics.findExpiringSoon = function(days = 7) {
  const warningTime = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  return this.find({
    expirationDate: { $lt: warningTime, $gt: new Date() },
    status: 'active'
  });
};

iocSchema.statics.getStatistics = function() {
  return this.aggregate([
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        active: {
          $sum: {
            $cond: [{ $eq: ['$status', 'active'] }, 1, 0]
          }
        },
        byType: {
          $push: {
            type: '$type',
            count: 1
          }
        },
        bySource: {
          $push: {
            source: '$source',
            count: 1
          }
        },
        avgConfidence: { $avg: '$confidence' },
        totalMatches: { $sum: '$statistics.totalMatches' },
      }
    }
  ]);
};

// Apply pagination plugin
iocSchema.plugin(mongoosePaginate);

const IOC = mongoose.model('IOC', iocSchema);

module.exports = IOC;