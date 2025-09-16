const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

// Network Behavioral Profile Schema
const networkBehaviorSchema = new mongoose.Schema({
  identifier: {
    type: String,
    required: true,
    index: true,
    // Can be IP address, device MAC, or subnet
  },
  identifierType: {
    type: String,
    enum: ['ip', 'mac', 'subnet', 'device'],
    required: true,
  },
  profilePeriod: {
    startDate: {
      type: Date,
      required: true,
    },
    endDate: {
      type: Date,
      required: true,
    },
  },
  trafficPatterns: {
    totalBytes: {
      inbound: { type: Number, default: 0 },
      outbound: { type: Number, default: 0 },
    },
    totalPackets: {
      inbound: { type: Number, default: 0 },
      outbound: { type: Number, default: 0 },
    },
    averageBytesPerSecond: {
      type: Number,
      default: 0,
    },
    peakTrafficHours: [{
      hour: { type: Number, min: 0, max: 23 },
      byteVolume: { type: Number, default: 0 },
    }],
    protocols: [{
      protocol: String, // TCP, UDP, ICMP, etc.
      bytesTransferred: { type: Number, default: 0 },
      packetCount: { type: Number, default: 0 },
      percentage: { type: Number, default: 0 },
    }],
    ports: [{
      port: { type: Number, min: 1, max: 65535 },
      protocol: String,
      connections: { type: Number, default: 0 },
      bytesTransferred: { type: Number, default: 0 },
      direction: { type: String, enum: ['inbound', 'outbound', 'both'] },
    }],
  },
  connectionPatterns: {
    uniqueConnections: {
      type: Number,
      default: 0,
    },
    averageConnectionDuration: {
      type: Number, // in seconds
      default: 0,
    },
    commonDestinations: [{
      destination: String, // IP or domain
      connections: { type: Number, default: 0 },
      bytesTransferred: { type: Number, default: 0 },
      ports: [{ type: Number }],
      lastConnection: { type: Date },
    }],
    connectionStates: [{
      state: String, // ESTABLISHED, TIME_WAIT, etc.
      count: { type: Number, default: 0 },
    }],
    failedConnections: {
      count: { type: Number, default: 0 },
      commonReasons: [{
        reason: String,
        count: { type: Number, default: 0 },
      }],
    },
  },
  geolocation: {
    country: String,
    region: String,
    city: String,
    asn: String,
    organization: String,
    isProxy: { type: Boolean, default: false },
    isTor: { type: Boolean, default: false },
    reputation: {
      score: { type: Number, min: 0, max: 100, default: 50 },
      sources: [String],
    },
  },
  securityEvents: {
    deniedConnections: { type: Number, default: 0 },
    securityRuleViolations: { type: Number, default: 0 },
    malwareAttempts: { type: Number, default: 0 },
    suspiciousPatterns: [{
      pattern: String,
      count: { type: Number, default: 0 },
      lastOccurrence: { type: Date },
    }],
  },
  riskScores: {
    overall: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    trafficRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    connectionRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    geoRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    behaviorRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
  },
  anomalies: [{
    type: {
      type: String,
      enum: ['traffic_spike', 'unusual_protocol', 'new_destination', 'port_scan', 'data_exfiltration', 'lateral_movement', 'other'],
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
    },
    description: String,
    timestamp: { type: Date, default: Date.now },
    resolved: { type: Boolean, default: false },
    riskScore: { type: Number, min: 0, max: 100 },
    evidence: {
      trafficVolume: Number,
      destinations: [String],
      protocols: [String],
      duration: Number,
    },
  }],
  mlAnalysis: {
    anomalies: {
      detections: [{
        type: String,
        feature: String,
        method: String,
        score: Number,
        value: Number,
        baseline: mongoose.Schema.Types.Mixed,
        severity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
      }],
      scores: mongoose.Schema.Types.Mixed,
      ensembleScore: { type: Number, default: 0 },
      isAnomalous: { type: Boolean, default: false },
    },
    trafficClassification: {
      category: String,
      confidence: Number,
      protocols: [String],
    },
    threatDetection: {
      level: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
      threats: [String],
      confidence: Number,
    },
    communicationPatterns: {
      patterns: [String],
      anomalies: [String],
    },
    features: mongoose.Schema.Types.Mixed,
    timestamp: { type: Date, default: Date.now },
  },
  mlPredictions: {
    isMalicious: {
      probability: { type: Number, min: 0, max: 1, default: 0 },
      confidence: { type: Number, min: 0, max: 1, default: 0 },
      lastPrediction: { type: Date },
      model: String,
    },
    classification: {
      category: String, // 'normal', 'suspicious', 'malicious'
      subcategory: String,
      confidence: { type: Number, min: 0, max: 1, default: 0 },
    },
  },
  lastUpdated: {
    type: Date,
    default: Date.now,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
}, {
  timestamps: true,
});

// Indexes for better performance
networkBehaviorSchema.index({ identifier: 1, identifierType: 1 });
networkBehaviorSchema.index({ 'profilePeriod.startDate': 1 });
networkBehaviorSchema.index({ 'riskScores.overall': -1 });
networkBehaviorSchema.index({ 'anomalies.severity': 1, 'anomalies.resolved': 1 });
networkBehaviorSchema.index({ 'mlPredictions.isMalicious.probability': -1 });
networkBehaviorSchema.index({ lastUpdated: 1 });

// Add pagination plugin
networkBehaviorSchema.plugin(mongoosePaginate);

const NetworkBehavior = mongoose.model('NetworkBehavior', networkBehaviorSchema);

module.exports = NetworkBehavior;