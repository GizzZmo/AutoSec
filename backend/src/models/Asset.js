/**
 * Asset Model
 * Represents discovered network and cloud assets for attack surface management
 */

const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

// Asset Schema
const assetSchema = new mongoose.Schema({
  assetId: {
    type: String,
    unique: true,
    index: true,
  },
  type: {
    type: String,
    enum: ['host', 'domain', 'service', 'application', 'database', 'cloud_instance', 'container', 'network_device'],
    required: true,
    index: true,
  },
  name: {
    type: String,
    index: true,
  },
  hostname: {
    type: String,
    index: true,
  },
  ipAddress: {
    type: String,
    index: true,
    validate: {
      validator: function(v) {
        if (!v) return true; // Optional field
        return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(v);
      },
      message: props => `${props.value} is not a valid IP address!`
    }
  },
  domain: {
    type: String,
    index: true,
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'unknown', 'decommissioned'],
    default: 'active',
    index: true,
  },
  criticality: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'unknown'],
    default: 'unknown',
    index: true,
  },
  environment: {
    type: String,
    enum: ['production', 'staging', 'development', 'testing', 'unknown'],
    default: 'unknown',
    index: true,
  },
  operatingSystem: {
    family: String, // Windows, Linux, macOS, etc.
    version: String,
    architecture: String, // x86, x64, arm, etc.
    kernelVersion: String,
    lastPatchDate: Date,
  },
  network: {
    macAddress: String,
    subnet: String,
    vlan: String,
    gateway: String,
    dnsServers: [String],
    networkInterfaces: [{
      name: String,
      ipAddress: String,
      macAddress: String,
      type: String, // ethernet, wifi, loopback, etc.
    }],
  },
  location: {
    physical: {
      datacenter: String,
      rack: String,
      building: String,
      floor: String,
      room: String,
    },
    geographical: {
      country: String,
      region: String,
      city: String,
      coordinates: {
        latitude: Number,
        longitude: Number,
      },
    },
    cloud: {
      provider: String, // aws, azure, gcp, etc.
      region: String,
      zone: String,
      accountId: String,
      subscriptionId: String,
      projectId: String,
    },
  },
  services: [{
    port: {
      type: Number,
      required: true,
      min: 1,
      max: 65535,
    },
    protocol: {
      type: String,
      enum: ['tcp', 'udp'],
      default: 'tcp',
    },
    service: String, // HTTP, SSH, MySQL, etc.
    version: String,
    state: {
      type: String,
      enum: ['open', 'closed', 'filtered'],
      default: 'open',
    },
    banner: String,
    ssl: {
      enabled: Boolean,
      certificate: {
        subject: String,
        issuer: String,
        validFrom: Date,
        validTo: Date,
        fingerprint: String,
      },
    },
    webInfo: {
      server: String,
      statusCode: Number,
      title: String,
      technologies: [String],
      redirects: [String],
      size: Number,
    },
    databaseInfo: {
      type: String,
      version: String,
      accessible: Boolean,
      authentication: Boolean,
    },
  }],
  applications: [{
    name: {
      type: String,
      required: true,
    },
    version: String,
    vendor: String,
    type: String, // web, desktop, mobile, service, etc.
    framework: String,
    language: String,
    webserver: String,
    database: String,
    installPath: String,
    configFiles: [String],
    ports: [Number],
    urls: [String],
    lastUpdated: Date,
  }],
  vulnerabilities: [{
    cveId: String,
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'info'],
    },
    score: {
      type: Number,
      min: 0,
      max: 10,
    },
    description: String,
    affectedComponent: String,
    detectionDate: { type: Date, default: Date.now },
    status: {
      type: String,
      enum: ['open', 'mitigated', 'fixed', 'accepted', 'false_positive'],
      default: 'open',
    },
    source: String, // nessus, openvas, manual, etc.
    patchAvailable: Boolean,
    exploitAvailable: Boolean,
    mitigation: String,
  }],
  compliance: {
    frameworks: [String], // SOC2, ISO27001, NIST, PCI, etc.
    requirements: [{
      framework: String,
      requirement: String,
      status: {
        type: String,
        enum: ['compliant', 'non_compliant', 'not_applicable', 'unknown'],
      },
      evidence: String,
      lastAssessed: Date,
    }],
    dataClassification: {
      type: String,
      enum: ['public', 'internal', 'confidential', 'restricted'],
      default: 'internal',
    },
    dataTypes: [String], // PII, PHI, financial, etc.
  },
  security: {
    endpoint: {
      antivirus: {
        installed: Boolean,
        product: String,
        version: String,
        lastUpdate: Date,
        status: String,
      },
      firewall: {
        enabled: Boolean,
        product: String,
        rules: Number,
      },
      encryption: {
        diskEncryption: Boolean,
        networkEncryption: Boolean,
        databaseEncryption: Boolean,
      },
    },
    access: {
      localUsers: [{
        username: String,
        isAdmin: Boolean,
        lastLogin: Date,
        status: String,
      }],
      remoteAccess: {
        ssh: Boolean,
        rdp: Boolean,
        vnc: Boolean,
      },
      authentication: {
        methods: [String], // password, key, certificate, mfa
        mfaEnabled: Boolean,
      },
    },
    monitoring: {
      logForwarding: Boolean,
      agentInstalled: Boolean,
      agentVersion: String,
      lastHeartbeat: Date,
    },
  },
  ownership: {
    owner: String,
    department: String,
    businessUnit: String,
    technicalContact: String,
    businessContact: String,
    costCenter: String,
  },
  discovery: {
    method: {
      type: String,
      enum: ['network_scan', 'dns_enumeration', 'cloud_api', 'agent_report', 'manual', 'integration'],
      required: true,
    },
    source: String,
    firstSeen: {
      type: Date,
      default: Date.now,
      index: true,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
      index: true,
    },
    scanHistory: [{
      timestamp: { type: Date, default: Date.now },
      method: String,
      source: String,
      changes: mongoose.Schema.Types.Mixed,
    }],
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 80,
    },
  },
  tags: [{
    type: String,
    index: true,
  }],
  metadata: {
    cloudMetadata: {
      instanceId: String,
      instanceType: String,
      imageId: String,
      securityGroups: [String],
      tags: mongoose.Schema.Types.Mixed,
    },
    containerMetadata: {
      containerId: String,
      image: String,
      imageTag: String,
      orchestrator: String, // docker, kubernetes, etc.
      namespace: String,
      labels: mongoose.Schema.Types.Mixed,
    },
    networkMetadata: {
      deviceType: String, // router, switch, firewall, etc.
      vendor: String,
      model: String,
      firmwareVersion: String,
      managementInterface: String,
    },
    customMetadata: mongoose.Schema.Types.Mixed,
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
    index: true,
  },
  riskFactors: [{
    factor: String,
    weight: Number,
    score: Number,
    description: String,
  }],
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Compound indexes for better query performance
assetSchema.index({ type: 1, status: 1 });
assetSchema.index({ 'discovery.lastSeen': -1 });
assetSchema.index({ environment: 1, criticality: 1 });
assetSchema.index({ 'location.cloud.provider': 1, 'location.cloud.region': 1 });
assetSchema.index({ tags: 1, status: 1 });
assetSchema.index({ riskScore: -1 });

// Text index for searching
assetSchema.index({
  name: 'text',
  hostname: 'text',
  'applications.name': 'text',
  tags: 'text'
});

// Virtual for asset age
assetSchema.virtual('age').get(function() {
  return Date.now() - this.discovery.firstSeen.getTime();
});

// Virtual for staleness (time since last seen)
assetSchema.virtual('staleness').get(function() {
  return Date.now() - this.discovery.lastSeen.getTime();
});

// Virtual for vulnerability count
assetSchema.virtual('vulnerabilityCount').get(function() {
  return this.vulnerabilities ? this.vulnerabilities.length : 0;
});

// Virtual for critical vulnerability count
assetSchema.virtual('criticalVulnerabilityCount').get(function() {
  return this.vulnerabilities ? 
    this.vulnerabilities.filter(v => v.severity === 'critical').length : 0;
});

// Virtual for service count
assetSchema.virtual('serviceCount').get(function() {
  return this.services ? this.services.length : 0;
});

// Virtual for exposure level
assetSchema.virtual('exposureLevel').get(function() {
  const publicServices = this.services?.filter(s => 
    [80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995].includes(s.port)
  ).length || 0;
  
  if (publicServices >= 5) return 'high';
  if (publicServices >= 3) return 'medium';
  if (publicServices >= 1) return 'low';
  return 'none';
});

// Pre-save middleware
assetSchema.pre('save', function(next) {
  // Auto-generate assetId if not provided
  if (this.isNew && !this.assetId) {
    this.assetId = `asset-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
  }

  // Update lastSeen timestamp
  this.discovery.lastSeen = new Date();

  // Calculate risk score
  this.calculateRiskScore();

  // Auto-detect criticality if not set
  if (this.criticality === 'unknown') {
    this.detectCriticality();
  }

  next();
});

// Instance methods
assetSchema.methods.calculateRiskScore = function() {
  let riskScore = 0;
  const riskFactors = [];

  // Vulnerability risk
  const criticalVulns = this.vulnerabilities?.filter(v => v.severity === 'critical').length || 0;
  const highVulns = this.vulnerabilities?.filter(v => v.severity === 'high').length || 0;
  const vulnRisk = Math.min(50, (criticalVulns * 15) + (highVulns * 5));
  
  if (vulnRisk > 0) {
    riskScore += vulnRisk;
    riskFactors.push({
      factor: 'vulnerabilities',
      weight: 0.5,
      score: vulnRisk,
      description: `${criticalVulns} critical, ${highVulns} high vulnerabilities`
    });
  }

  // Exposure risk (based on open services)
  const exposedServices = this.services?.filter(s => s.state === 'open').length || 0;
  const exposureRisk = Math.min(20, exposedServices * 2);
  
  if (exposureRisk > 0) {
    riskScore += exposureRisk;
    riskFactors.push({
      factor: 'service_exposure',
      weight: 0.2,
      score: exposureRisk,
      description: `${exposedServices} exposed services`
    });
  }

  // Environment risk
  if (this.environment === 'production') {
    riskScore += 10;
    riskFactors.push({
      factor: 'environment',
      weight: 0.1,
      score: 10,
      description: 'Production environment'
    });
  }

  // Criticality risk
  const criticalityRisk = {
    'critical': 15,
    'high': 10,
    'medium': 5,
    'low': 2,
    'unknown': 0
  }[this.criticality] || 0;

  if (criticalityRisk > 0) {
    riskScore += criticalityRisk;
    riskFactors.push({
      factor: 'criticality',
      weight: 0.15,
      score: criticalityRisk,
      description: `${this.criticality} criticality asset`
    });
  }

  // Staleness risk (assets not seen recently)
  const staleness = Date.now() - this.discovery.lastSeen.getTime();
  const stalenessHours = staleness / (1000 * 60 * 60);
  
  if (stalenessHours > 168) { // More than a week
    const stalenessRisk = Math.min(5, Math.floor(stalenessHours / 168));
    riskScore += stalenessRisk;
    riskFactors.push({
      factor: 'staleness',
      weight: 0.05,
      score: stalenessRisk,
      description: `Not seen for ${Math.floor(stalenessHours / 24)} days`
    });
  }

  this.riskScore = Math.min(100, Math.max(0, riskScore));
  this.riskFactors = riskFactors;
};

assetSchema.methods.detectCriticality = function() {
  // Auto-detect criticality based on services and applications
  const criticalServices = [443, 80, 22, 3389, 5432, 3306]; // HTTPS, HTTP, SSH, RDP, PostgreSQL, MySQL
  const hasWebServices = this.services?.some(s => [80, 443].includes(s.port));
  const hasDatabaseServices = this.services?.some(s => [3306, 5432, 27017].includes(s.port));
  const hasRemoteAccess = this.services?.some(s => [22, 3389].includes(s.port));

  if (this.environment === 'production') {
    if (hasDatabaseServices) {
      this.criticality = 'critical';
    } else if (hasWebServices) {
      this.criticality = 'high';
    } else if (hasRemoteAccess) {
      this.criticality = 'medium';
    } else {
      this.criticality = 'low';
    }
  } else if (this.environment === 'staging') {
    this.criticality = 'medium';
  } else {
    this.criticality = 'low';
  }
};

assetSchema.methods.addVulnerability = function(vulnerability) {
  this.vulnerabilities.push({
    ...vulnerability,
    detectionDate: new Date(),
  });
  return this.save();
};

assetSchema.methods.updateService = function(port, serviceInfo) {
  const existingService = this.services.find(s => s.port === port);
  
  if (existingService) {
    Object.assign(existingService, serviceInfo);
  } else {
    this.services.push({ port, ...serviceInfo });
  }
  
  return this.save();
};

assetSchema.methods.markAsInactive = function() {
  this.status = 'inactive';
  this.discovery.lastSeen = new Date();
  return this.save();
};

assetSchema.methods.addTag = function(tag) {
  if (!this.tags.includes(tag)) {
    this.tags.push(tag);
  }
  return this.save();
};

assetSchema.methods.removeTag = function(tag) {
  this.tags = this.tags.filter(t => t !== tag);
  return this.save();
};

assetSchema.methods.updateDiscovery = function(method, source, changes = {}) {
  this.discovery.method = method;
  this.discovery.source = source;
  this.discovery.lastSeen = new Date();
  
  this.discovery.scanHistory.push({
    timestamp: new Date(),
    method,
    source,
    changes,
  });

  // Keep only last 50 scan history entries
  if (this.discovery.scanHistory.length > 50) {
    this.discovery.scanHistory = this.discovery.scanHistory.slice(-50);
  }

  return this.save();
};

// Static methods
assetSchema.statics.findByType = function(type) {
  return this.find({ type, status: 'active' });
};

assetSchema.statics.findCritical = function() {
  return this.find({ 
    criticality: { $in: ['critical', 'high'] },
    status: 'active'
  });
};

assetSchema.statics.findVulnerable = function() {
  return this.find({
    'vulnerabilities.0': { $exists: true },
    status: 'active'
  });
};

assetSchema.statics.findStale = function(days = 7) {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return this.find({
    'discovery.lastSeen': { $lt: cutoff },
    status: 'active'
  });
};

assetSchema.statics.findByEnvironment = function(environment) {
  return this.find({ environment, status: 'active' });
};

assetSchema.statics.findByRiskScore = function(minScore = 70) {
  return this.find({
    riskScore: { $gte: minScore },
    status: 'active'
  }).sort({ riskScore: -1 });
};

assetSchema.statics.getStatistics = function() {
  return this.aggregate([
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        active: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        byType: {
          $push: {
            type: '$type',
            count: 1
          }
        },
        byEnvironment: {
          $push: {
            environment: '$environment',
            count: 1
          }
        },
        byCriticality: {
          $push: {
            criticality: '$criticality',
            count: 1
          }
        },
        avgRiskScore: { $avg: '$riskScore' },
        totalVulnerabilities: { $sum: { $size: '$vulnerabilities' } },
        criticalVulnerabilities: {
          $sum: {
            $size: {
              $filter: {
                input: '$vulnerabilities',
                cond: { $eq: ['$$this.severity', 'critical'] }
              }
            }
          }
        }
      }
    }
  ]);
};

// Apply pagination plugin
assetSchema.plugin(mongoosePaginate);

const Asset = mongoose.model('Asset', assetSchema);

module.exports = Asset;