const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

// User Behavioral Profile Schema
const userBehaviorSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    index: true,
  },
  username: {
    type: String,
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
  loginPatterns: {
    averageLoginsPerDay: {
      type: Number,
      default: 0,
    },
    commonLoginHours: [{
      hour: { type: Number, min: 0, max: 23 },
      frequency: { type: Number, default: 0 },
    }],
    commonLoginDays: [{
      dayOfWeek: { type: Number, min: 0, max: 6 },
      frequency: { type: Number, default: 0 },
    }],
    averageSessionDuration: {
      type: Number, // in minutes
      default: 0,
    },
    geolocations: [{
      country: String,
      region: String,
      city: String,
      frequency: { type: Number, default: 0 },
      lastSeen: { type: Date },
    }],
    devices: [{
      userAgent: String,
      deviceFingerprint: String,
      frequency: { type: Number, default: 0 },
      lastSeen: { type: Date },
    }],
    ipAddresses: [{
      ip: String,
      frequency: { type: Number, default: 0 },
      lastSeen: { type: Date },
    }],
  },
  activityPatterns: {
    averageActionsPerSession: {
      type: Number,
      default: 0,
    },
    commonActions: [{
      action: String,
      frequency: { type: Number, default: 0 },
    }],
    dataAccess: [{
      resource: String,
      frequency: { type: Number, default: 0 },
      lastAccessed: { type: Date },
    }],
    fileOperations: {
      downloads: { type: Number, default: 0 },
      uploads: { type: Number, default: 0 },
      modifications: { type: Number, default: 0 },
    },
  },
  riskScores: {
    overall: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    loginRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    activityRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    deviceRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    locationRisk: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
  },
  anomalies: [{
    type: {
      type: String,
      enum: ['login_time', 'login_location', 'device_change', 'activity_spike', 'data_access', 'other'],
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
    },
    description: String,
    timestamp: { type: Date, default: Date.now },
    resolved: { type: Boolean, default: false },
    riskScore: { type: Number, min: 0, max: 100 },
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
    riskScore: {
      overall: { type: Number, min: 0, max: 100, default: 0 },
      components: mongoose.Schema.Types.Mixed,
      risk_level: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
    },
    classification: {
      category: { type: String, enum: ['normal', 'unusual', 'suspicious', 'highly_suspicious'] },
      confidence: { type: Number, min: 0, max: 1, default: 0.5 },
      patterns: [String],
      reasoning: String,
    },
    patterns: mongoose.Schema.Types.Mixed,
    predictions: {
      nextLoginTime: Date,
      riskTrend: { type: String, enum: ['increasing', 'stable', 'decreasing'] },
      confidence: { type: Number, min: 0, max: 1, default: 0.5 },
    },
    insights: [{
      type: String,
      message: String,
      severity: { type: String, enum: ['low', 'medium', 'high'] },
    }],
    features: mongoose.Schema.Types.Mixed,
    timestamp: { type: Date, default: Date.now },
    modelVersions: mongoose.Schema.Types.Mixed,
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
userBehaviorSchema.index({ userId: 1, 'profilePeriod.startDate': 1 });
userBehaviorSchema.index({ 'riskScores.overall': -1 });
userBehaviorSchema.index({ 'anomalies.severity': 1, 'anomalies.resolved': 1 });
userBehaviorSchema.index({ lastUpdated: 1 });

// Add pagination plugin
userBehaviorSchema.plugin(mongoosePaginate);

const UserBehavior = mongoose.model('UserBehavior', userBehaviorSchema);

module.exports = UserBehavior;