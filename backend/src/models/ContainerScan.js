/**
 * Container Scan Model
 * Represents container security scan results
 */

const mongoose = require('mongoose');

const containerScanSchema = new mongoose.Schema({
  scanId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  imageUrl: {
    type: String,
    required: true,
    index: true
  },
  scanner: {
    type: String,
    enum: ['trivy', 'clair', 'grype'],
    default: 'trivy'
  },
  status: {
    type: String,
    enum: ['pending', 'running', 'completed', 'failed'],
    default: 'pending',
    index: true
  },
  results: {
    vulnerabilities: [{
      id: String,
      package: String,
      version: String,
      fixedVersion: String,
      severity: {
        type: String,
        enum: ['critical', 'high', 'medium', 'low', 'unknown']
      },
      title: String,
      description: String,
      references: [String],
      cvss: mongoose.Schema.Types.Mixed,
      target: String
    }],
    secrets: [{
      type: String,
      category: String,
      severity: String,
      title: String,
      startLine: Number,
      endLine: Number,
      code: [String],
      target: String
    }],
    misconfigurations: [{
      id: String,
      type: String,
      title: String,
      description: String,
      severity: String,
      message: String,
      resolution: String,
      target: String
    }],
    analysis: {
      summary: {
        total: Number,
        critical: Number,
        high: Number,
        medium: Number,
        low: Number,
        unknown: Number
      },
      topVulnerabilities: [mongoose.Schema.Types.Mixed],
      packageAnalysis: [mongoose.Schema.Types.Mixed],
      secretsFound: Number,
      misconfigurationsFound: Number,
      trends: mongoose.Schema.Types.Mixed
    },
    recommendations: [{
      priority: String,
      category: String,
      title: String,
      description: String,
      actions: [String]
    }],
    riskScore: {
      score: Number,
      level: String,
      factors: mongoose.Schema.Types.Mixed
    },
    metadata: {
      imageSize: Number,
      layers: Number,
      baseImage: String,
      totalPackages: Number
    },
    startTime: Date,
    endTime: Date,
    duration: Number
  }
}, {
  timestamps: true
});

// Indexes
containerScanSchema.index({ userId: 1, createdAt: -1 });
containerScanSchema.index({ status: 1 });
containerScanSchema.index({ 'results.riskScore.score': -1 });
containerScanSchema.index({ 'results.analysis.summary.critical': -1 });

// Virtual for total vulnerabilities
containerScanSchema.virtual('totalVulnerabilities').get(function() {
  return this.results?.vulnerabilities?.length || 0;
});

// Virtual for critical vulnerabilities
containerScanSchema.virtual('criticalVulnerabilities').get(function() {
  return this.results?.analysis?.summary?.critical || 0;
});

// Instance methods
containerScanSchema.methods.getRiskLevel = function() {
  return this.results?.riskScore?.level || 'unknown';
};

containerScanSchema.methods.hasCriticalIssues = function() {
  const critical = this.results?.analysis?.summary?.critical || 0;
  const secrets = this.results?.analysis?.secretsFound || 0;
  return critical > 0 || secrets > 0;
};

// Static methods
containerScanSchema.statics.findByUser = function(userId, options = {}) {
  const query = { userId };
  
  if (options.status) {
    query.status = options.status;
  }
  
  if (options.imageUrl) {
    query.imageUrl = new RegExp(options.imageUrl, 'i');
  }

  return this.find(query)
    .populate('userId', 'username email')
    .sort({ createdAt: -1 })
    .limit(options.limit || 50);
};

containerScanSchema.statics.findHighRisk = function(userId) {
  return this.find({
    userId,
    status: 'completed',
    $or: [
      { 'results.riskScore.score': { $gte: 70 } },
      { 'results.analysis.summary.critical': { $gt: 0 } },
      { 'results.analysis.secretsFound': { $gt: 0 } }
    ]
  })
  .sort({ 'results.riskScore.score': -1 })
  .limit(20);
};

containerScanSchema.statics.getStatistics = function(userId) {
  return this.aggregate([
    { $match: { userId: mongoose.Types.ObjectId(userId), status: 'completed' } },
    {
      $group: {
        _id: null,
        totalScans: { $sum: 1 },
        avgRiskScore: { $avg: '$results.riskScore.score' },
        totalVulnerabilities: { $sum: '$results.analysis.summary.total' },
        totalCritical: { $sum: '$results.analysis.summary.critical' },
        totalHigh: { $sum: '$results.analysis.summary.high' },
        totalSecrets: { $sum: '$results.analysis.secretsFound' },
        avgScanTime: { $avg: '$results.duration' }
      }
    }
  ]);
};

const ContainerScan = mongoose.model('ContainerScan', containerScanSchema);
module.exports = ContainerScan;