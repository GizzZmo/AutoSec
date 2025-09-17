/**
 * Playbook Model
 * Represents automated response playbooks for incident response
 */

const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

// Playbook Schema
const playbookSchema = new mongoose.Schema({
  playbookId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  name: {
    type: String,
    required: true,
    maxlength: 200,
  },
  description: {
    type: String,
    required: true,
    maxlength: 1000,
  },
  version: {
    type: String,
    default: '1.0.0',
  },
  category: {
    type: String,
    enum: ['containment', 'investigation', 'eradication', 'recovery', 'communication', 'escalation', 'compliance'],
    required: true,
  },
  severity: {
    type: [String],
    enum: ['info', 'low', 'medium', 'high', 'critical'],
    default: ['medium'],
  },
  active: {
    type: Boolean,
    default: true,
    index: true,
  },
  requiresApproval: {
    type: Boolean,
    default: false,
  },
  author: {
    type: String,
    required: true,
  },
  maintainer: {
    type: String,
    required: true,
  },
  triggers: [{
    type: {
      type: String,
      enum: ['incident', 'threat_event', 'manual', 'scheduled', 'escalation'],
      required: true,
    },
    conditions: [{
      field: String,
      operator: {
        type: String,
        enum: ['equals', 'not_equals', 'greater_than', 'less_than', 'greater_equal', 'less_equal', 'contains', 'starts_with', 'ends_with', 'regex', 'in'],
      },
      value: mongoose.Schema.Types.Mixed,
    }],
    priority: {
      type: Number,
      default: 50,
      min: 1,
      max: 100,
    },
  }],
  workflow: {
    steps: [{
      stepId: {
        type: String,
        required: true,
      },
      name: {
        type: String,
        required: true,
      },
      description: String,
      type: {
        type: String,
        enum: ['action', 'decision', 'parallel', 'loop', 'delay', 'manual', 'notification', 'integration'],
        required: true,
      },
      config: mongoose.Schema.Types.Mixed,
      dependencies: [String], // Array of stepIds that must complete first
      timeout: {
        type: Number,
        default: 300, // 5 minutes
      },
      retryPolicy: {
        maxRetries: {
          type: Number,
          default: 0,
        },
        retryDelay: {
          type: Number,
          default: 30, // seconds
        },
        retryConditions: [String],
      },
      errorHandling: {
        onError: {
          type: String,
          enum: ['stop', 'continue', 'retry', 'escalate'],
          default: 'stop',
        },
        errorNotification: Boolean,
        fallbackStep: String,
      },
      outputMapping: [{
        source: String,
        target: String,
        transform: String,
      }],
    }],
    variables: [{
      name: String,
      type: {
        type: String,
        enum: ['string', 'number', 'boolean', 'array', 'object'],
      },
      defaultValue: mongoose.Schema.Types.Mixed,
      required: Boolean,
      description: String,
    }],
    parallelism: {
      type: Number,
      default: 1,
      min: 1,
      max: 10,
    },
  },
  integrations: [{
    type: {
      type: String,
      enum: ['firewall', 'siem', 'vulnerability_scanner', 'ticketing', 'notification', 'sdn', 'iam'],
    },
    name: String,
    config: mongoose.Schema.Types.Mixed,
    required: {
      type: Boolean,
      default: false,
    },
  }],
  permissions: {
    executeRoles: [String],
    approveRoles: [String],
    editRoles: [String],
    viewRoles: [String],
  },
  testing: {
    lastTested: Date,
    testResults: [{
      timestamp: { type: Date, default: Date.now },
      tester: String,
      result: {
        type: String,
        enum: ['passed', 'failed', 'partial'],
      },
      details: String,
      executionTime: Number,
      stepsExecuted: Number,
      stepsFailed: Number,
    }],
    validationCriteria: [String],
  },
  metrics: {
    totalExecutions: {
      type: Number,
      default: 0,
    },
    successfulExecutions: {
      type: Number,
      default: 0,
    },
    failedExecutions: {
      type: Number,
      default: 0,
    },
    averageExecutionTime: {
      type: Number,
      default: 0,
    },
    lastExecuted: Date,
    effectiveness: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
  },
  documentation: {
    overview: String,
    prerequisites: [String],
    expectedOutcomes: [String],
    rollbackProcedure: String,
    notes: [String],
    attachments: [{
      name: String,
      path: String,
      type: String,
      uploadedAt: { type: Date, default: Date.now },
    }],
  },
  compliance: {
    standards: [String], // ISO 27001, NIST, SOC 2, etc.
    requirements: [String],
    evidenceCollection: Boolean,
    auditTrail: Boolean,
  },
  tags: [{
    type: String,
    index: true,
  }],
  changelog: [{
    version: String,
    timestamp: { type: Date, default: Date.now },
    author: String,
    changes: [String],
    reason: String,
  }],
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better query performance
playbookSchema.index({ category: 1, active: 1 });
playbookSchema.index({ 'triggers.type': 1, active: 1 });
playbookSchema.index({ severity: 1, active: 1 });
playbookSchema.index({ tags: 1 });
playbookSchema.index({ 'metrics.effectiveness': -1 });

// Text index for searching
playbookSchema.index({
  name: 'text',
  description: 'text',
  'documentation.overview': 'text',
  tags: 'text'
});

// Virtual for success rate
playbookSchema.virtual('successRate').get(function() {
  if (this.metrics.totalExecutions === 0) return 0;
  return (this.metrics.successfulExecutions / this.metrics.totalExecutions) * 100;
});

// Virtual for complexity score
playbookSchema.virtual('complexityScore').get(function() {
  const stepCount = this.workflow.steps.length;
  const dependencyCount = this.workflow.steps.reduce((acc, step) => acc + (step.dependencies?.length || 0), 0);
  const integrationCount = this.integrations.length;
  
  // Simple complexity calculation
  return Math.min(100, (stepCount * 2) + dependencyCount + (integrationCount * 3));
});

// Virtual for risk level
playbookSchema.virtual('riskLevel').get(function() {
  let riskScore = 0;
  
  // Higher risk for critical severity
  if (this.severity.includes('critical')) riskScore += 30;
  if (this.severity.includes('high')) riskScore += 20;
  
  // Higher risk for destructive actions
  const destructiveActions = ['block_ip', 'disable_user', 'quarantine_file', 'shutdown_system'];
  const hasDestructiveActions = this.workflow.steps.some(step => 
    destructiveActions.some(action => step.config?.action?.includes(action))
  );
  if (hasDestructiveActions) riskScore += 25;
  
  // Higher risk if no approval required
  if (!this.requiresApproval) riskScore += 15;
  
  // Higher risk for untested playbooks
  if (!this.testing.lastTested) riskScore += 20;
  
  if (riskScore >= 70) return 'high';
  if (riskScore >= 40) return 'medium';
  return 'low';
});

// Pre-save middleware
playbookSchema.pre('save', function(next) {
  // Auto-generate playbookId if not provided
  if (this.isNew && !this.playbookId) {
    this.playbookId = `PB-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`;
  }

  // Validate workflow steps
  if (this.isModified('workflow')) {
    const stepIds = this.workflow.steps.map(step => step.stepId);
    const duplicateIds = stepIds.filter((id, index) => stepIds.indexOf(id) !== index);
    
    if (duplicateIds.length > 0) {
      return next(new Error(`Duplicate step IDs found: ${duplicateIds.join(', ')}`));
    }

    // Validate dependencies
    for (const step of this.workflow.steps) {
      if (step.dependencies) {
        const invalidDeps = step.dependencies.filter(dep => !stepIds.includes(dep));
        if (invalidDeps.length > 0) {
          return next(new Error(`Invalid dependencies for step ${step.stepId}: ${invalidDeps.join(', ')}`));
        }
      }
    }
  }

  next();
});

// Instance methods
playbookSchema.methods.recordExecution = function(result) {
  this.metrics.totalExecutions += 1;
  this.metrics.lastExecuted = new Date();
  
  if (result.status === 'completed') {
    this.metrics.successfulExecutions += 1;
  } else {
    this.metrics.failedExecutions += 1;
  }

  // Update average execution time
  if (result.executionTime) {
    const total = this.metrics.averageExecutionTime * (this.metrics.totalExecutions - 1);
    this.metrics.averageExecutionTime = (total + result.executionTime) / this.metrics.totalExecutions;
  }

  // Update effectiveness score
  this.metrics.effectiveness = this.successRate;

  return this.save();
};

playbookSchema.methods.addTestResult = function(testResult) {
  this.testing.testResults.push(testResult);
  this.testing.lastTested = new Date();
  
  // Keep only last 10 test results
  if (this.testing.testResults.length > 10) {
    this.testing.testResults = this.testing.testResults.slice(-10);
  }

  return this.save();
};

playbookSchema.methods.createNewVersion = function(changes, author, reason) {
  const newVersion = this.incrementVersion(this.version);
  
  this.version = newVersion;
  this.changelog.push({
    version: newVersion,
    timestamp: new Date(),
    author,
    changes,
    reason,
  });

  return this.save();
};

playbookSchema.methods.incrementVersion = function(version) {
  const parts = version.split('.').map(Number);
  parts[2] += 1; // Increment patch version
  return parts.join('.');
};

playbookSchema.methods.validateTriggerConditions = function(context) {
  for (const trigger of this.triggers) {
    let allConditionsMet = true;

    for (const condition of trigger.conditions) {
      const value = this.getContextValue(context, condition.field);
      const conditionMet = this.evaluateCondition(value, condition.operator, condition.value);
      
      if (!conditionMet) {
        allConditionsMet = false;
        break;
      }
    }

    if (allConditionsMet) {
      return true;
    }
  }

  return false;
};

playbookSchema.methods.getContextValue = function(context, fieldPath) {
  const parts = fieldPath.split('.');
  let value = context;

  for (const part of parts) {
    if (value && typeof value === 'object' && part in value) {
      value = value[part];
    } else {
      return undefined;
    }
  }

  return value;
};

playbookSchema.methods.evaluateCondition = function(actualValue, operator, expectedValue) {
  switch (operator) {
    case 'equals':
      return actualValue === expectedValue;
    case 'not_equals':
      return actualValue !== expectedValue;
    case 'greater_than':
      return actualValue > expectedValue;
    case 'less_than':
      return actualValue < expectedValue;
    case 'greater_equal':
      return actualValue >= expectedValue;
    case 'less_equal':
      return actualValue <= expectedValue;
    case 'contains':
      return String(actualValue).includes(String(expectedValue));
    case 'starts_with':
      return String(actualValue).startsWith(String(expectedValue));
    case 'ends_with':
      return String(actualValue).endsWith(String(expectedValue));
    case 'regex':
      return new RegExp(expectedValue).test(String(actualValue));
    case 'in':
      return Array.isArray(expectedValue) && expectedValue.includes(actualValue);
    default:
      return false;
  }
};

playbookSchema.methods.getExecutionPlan = function() {
  const plan = {
    totalSteps: this.workflow.steps.length,
    estimatedTime: this.workflow.steps.reduce((acc, step) => acc + (step.timeout || 300), 0),
    requiredIntegrations: this.integrations.filter(i => i.required).map(i => i.type),
    riskLevel: this.riskLevel,
    approvalRequired: this.requiresApproval,
  };

  return plan;
};

// Static methods
playbookSchema.statics.findByCategory = function(category) {
  return this.find({ category, active: true });
};

playbookSchema.statics.findByTriggerType = function(triggerType) {
  return this.find({
    'triggers.type': triggerType,
    active: true
  });
};

playbookSchema.statics.findBySeverity = function(severity) {
  return this.find({
    severity: { $in: [severity] },
    active: true
  });
};

playbookSchema.statics.findMostEffective = function(limit = 10) {
  return this.find({ active: true })
    .sort({ 'metrics.effectiveness': -1 })
    .limit(limit);
};

playbookSchema.statics.findLeastTested = function(limit = 10) {
  return this.find({
    active: true,
    $or: [
      { 'testing.lastTested': { $exists: false } },
      { 'testing.lastTested': { $lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } } // 30 days ago
    ]
  }).limit(limit);
};

playbookSchema.statics.getStatistics = function() {
  return this.aggregate([
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        active: {
          $sum: { $cond: [{ $eq: ['$active', true] }, 1, 0] }
        },
        byCategory: {
          $push: {
            category: '$category',
            count: 1
          }
        },
        avgSuccessRate: {
          $avg: {
            $cond: [
              { $gt: ['$metrics.totalExecutions', 0] },
              { $multiply: [{ $divide: ['$metrics.successfulExecutions', '$metrics.totalExecutions'] }, 100] },
              0
            ]
          }
        },
        totalExecutions: { $sum: '$metrics.totalExecutions' },
        avgExecutionTime: { $avg: '$metrics.averageExecutionTime' },
      }
    }
  ]);
};

// Apply pagination plugin
playbookSchema.plugin(mongoosePaginate);

const Playbook = mongoose.model('Playbook', playbookSchema);

module.exports = Playbook;