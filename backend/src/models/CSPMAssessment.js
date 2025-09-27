/**
 * CSPM Assessment Model
 * Represents Cloud Security Posture Management assessment results
 */

const mongoose = require('mongoose');

const cspmAssessmentSchema = new mongoose.Schema({
  assessmentId: {
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
  status: {
    type: String,
    enum: ['pending', 'running', 'completed', 'failed'],
    default: 'pending',
    index: true
  },
  results: {
    providers: [{
      provider: String,
      name: String,
      resources: [{
        id: String,
        type: String,
        name: String,
        region: String,
        config: mongoose.Schema.Types.Mixed
      }],
      findings: [{
        id: String,
        rule: String,
        framework: String,
        title: String,
        description: String,
        riskLevel: String,
        resource: {
          id: String,
          type: String,
          name: String,
          provider: String,
          region: String
        },
        details: String,
        remediation: mongoose.Schema.Types.Mixed,
        evidence: mongoose.Schema.Types.Mixed,
        discoveredAt: Date
      }],
      summary: {
        totalResources: Number,
        compliantResources: Number,
        nonCompliantResources: Number,
        findingsByRisk: mongoose.Schema.Types.Mixed
      }
    }],
    summary: {
      totalResources: Number,
      compliantResources: Number,
      nonCompliantResources: Number,
      criticalFindings: Number,
      highFindings: Number,
      mediumFindings: Number,
      lowFindings: Number
    },
    compliance: mongoose.Schema.Types.Mixed,
    recommendations: [{
      priority: Number,
      riskLevel: String,
      title: String,
      description: String,
      findings: [mongoose.Schema.Types.Mixed],
      totalFindings: Number,
      estimatedEffort: Number,
      actions: [String]
    }]
  },
  metadata: {
    startTime: Date,
    endTime: Date,
    duration: Number,
    assessmentId: String
  }
}, {
  timestamps: true
});

// Indexes
cspmAssessmentSchema.index({ userId: 1, createdAt: -1 });
cspmAssessmentSchema.index({ status: 1 });
cspmAssessmentSchema.index({ 'results.summary.criticalFindings': -1 });

// Virtual for compliance score
cspmAssessmentSchema.virtual('overallComplianceScore').get(function() {
  if (!this.results || !this.results.summary) return 0;
  
  const { compliantResources, totalResources } = this.results.summary;
  if (totalResources === 0) return 0;
  
  return Math.round((compliantResources / totalResources) * 100);
});

// Static methods
cspmAssessmentSchema.statics.findByUser = function(userId, options = {}) {
  const query = { userId };
  
  if (options.status) {
    query.status = options.status;
  }

  return this.find(query)
    .populate('userId', 'username email')
    .sort({ createdAt: -1 })
    .limit(options.limit || 50);
};

cspmAssessmentSchema.statics.getLatestByUser = function(userId) {
  return this.findOne({ userId, status: 'completed' })
    .sort({ createdAt: -1 })
    .populate('userId', 'username email');
};

const CSPMAssessment = mongoose.model('CSPMAssessment', cspmAssessmentSchema);
module.exports = CSPMAssessment;