/**
 * Zero Trust Network Access (ZTNA) Service
 * Implements Zero Trust security model with continuous verification
 */

const logger = require('../config/logger');
const crypto = require('crypto');

class ZeroTrustService {
  constructor() {
    this.trustFactors = new Map([
      ['device_compliance', {
        weight: 0.25,
        validator: this.validateDeviceCompliance.bind(this)
      }],
      ['user_behavior', {
        weight: 0.20,
        validator: this.validateUserBehavior.bind(this)
      }],
      ['network_location', {
        weight: 0.15,
        validator: this.validateNetworkLocation.bind(this)
      }],
      ['authentication_strength', {
        weight: 0.20,
        validator: this.validateAuthenticationStrength.bind(this)
      }],
      ['time_context', {
        weight: 0.10,
        validator: this.validateTimeContext.bind(this)
      }],
      ['resource_sensitivity', {
        weight: 0.10,
        validator: this.validateResourceSensitivity.bind(this)
      }]
    ]);

    this.accessPolicies = new Map();
    this.trustLevels = {
      NONE: 0,
      LOW: 25,
      MEDIUM: 50,
      HIGH: 75,
      MAXIMUM: 100
    };

    this.initializePolicies();
  }

  /**
   * Evaluate access request using Zero Trust principles
   */
  async evaluateAccess(accessRequest) {
    try {
      const {
        userId,
        deviceId,
        resource,
        action,
        context = {}
      } = accessRequest;

      logger.info(`Evaluating Zero Trust access for user ${userId} to resource ${resource}`);

      // Calculate overall trust score
      const trustScore = await this.calculateTrustScore(accessRequest);
      
      // Get applicable policies
      const policies = await this.getApplicablePolicies(resource, action);
      
      // Evaluate policies
      const policyEvaluation = await this.evaluatePolicies(policies, accessRequest, trustScore);
      
      // Make access decision
      const decision = this.makeAccessDecision(trustScore, policyEvaluation);
      
      // Log decision
      await this.logAccessDecision(accessRequest, trustScore, decision);
      
      // Handle conditional access
      if (decision.result === 'conditional') {
        decision.requirements = await this.getAdditionalRequirements(accessRequest, trustScore);
      }

      return {
        allowed: decision.result === 'allow',
        trustScore,
        decision: decision.result,
        requirements: decision.requirements || [],
        policies: policyEvaluation.appliedPolicies,
        factors: decision.factors,
        sessionId: this.generateSecureSessionId(),
        expiresAt: new Date(Date.now() + this.getSessionDuration(trustScore))
      };

    } catch (error) {
      logger.error('Error in Zero Trust access evaluation:', error);
      
      // Default to deny on error
      return {
        allowed: false,
        trustScore: 0,
        decision: 'deny',
        error: 'Evaluation failed',
        policies: [],
        factors: {}
      };
    }
  }

  /**
   * Calculate overall trust score based on all factors
   */
  async calculateTrustScore(accessRequest) {
    const scores = new Map();
    let totalWeight = 0;
    let weightedSum = 0;

    for (const [factorName, factor] of this.trustFactors) {
      try {
        const score = await factor.validator(accessRequest);
        scores.set(factorName, score);
        
        weightedSum += score * factor.weight;
        totalWeight += factor.weight;
        
        logger.debug(`Trust factor ${factorName}: ${score} (weight: ${factor.weight})`);
      } catch (error) {
        logger.error(`Error evaluating trust factor ${factorName}:`, error);
        // Use lowest score on evaluation error
        scores.set(factorName, 0);
        totalWeight += factor.weight;
      }
    }

    const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
    
    return {
      overall: overallScore,
      factors: Object.fromEntries(scores),
      level: this.getTrustLevel(overallScore)
    };
  }

  /**
   * Validate device compliance
   */
  async validateDeviceCompliance(accessRequest) {
    const { deviceId, context } = accessRequest;
    
    if (!deviceId) {
      return this.trustLevels.NONE;
    }

    const Device = require('../models/Device');
    const device = await Device.findById(deviceId);
    
    if (!device) {
      logger.warn(`Unknown device attempting access: ${deviceId}`);
      return this.trustLevels.NONE;
    }

    let score = this.trustLevels.LOW;

    // Device registration status
    if (device.isManaged) {
      score += 20;
    }

    // OS and security patch level
    if (device.securityPatchLevel && this.isRecentPatchLevel(device.securityPatchLevel)) {
      score += 15;
    }

    // Anti-malware status
    if (device.antimalwareStatus === 'active' && device.lastScanDate > new Date(Date.now() - 24 * 60 * 60 * 1000)) {
      score += 15;
    }

    // Encryption status
    if (device.isEncrypted) {
      score += 10;
    }

    // Device certificate validation
    if (device.certificate && await this.validateDeviceCertificate(device.certificate)) {
      score += 15;
    }

    // Jailbreak/Root detection
    if (device.isJailbroken || device.isRooted) {
      score -= 30;
    }

    // Suspicious activity
    if (device.suspiciousActivity && device.suspiciousActivity.length > 0) {
      score -= 20;
    }

    return Math.max(this.trustLevels.NONE, Math.min(this.trustLevels.MAXIMUM, score));
  }

  /**
   * Validate user behavior patterns
   */
  async validateUserBehavior(accessRequest) {
    const { userId, context } = accessRequest;
    
    const UserBehavior = require('../models/UserBehavior');
    const behavior = await UserBehavior.findOne({ userId }).sort({ createdAt: -1 });
    
    if (!behavior) {
      return this.trustLevels.LOW;
    }

    let score = this.trustLevels.MEDIUM;

    // Risk score from behavioral analysis
    if (behavior.riskScores.overall < 20) {
      score += 25;
    } else if (behavior.riskScores.overall > 80) {
      score -= 30;
    }

    // Login patterns
    const currentHour = new Date().getHours();
    const typicalLoginHours = behavior.patterns.loginHours || [];
    
    if (typicalLoginHours.includes(currentHour)) {
      score += 10;
    } else if (typicalLoginHours.length > 0) {
      score -= 15;
    }

    // Location consistency
    if (context.ipAddress && behavior.patterns.commonLocations) {
      const geoIpService = require('./geoIpService');
      const currentLocation = geoIpService.lookup(context.ipAddress);
      
      if (currentLocation && this.isKnownLocation(currentLocation, behavior.patterns.commonLocations)) {
        score += 15;
      } else {
        score -= 10;
      }
    }

    // Recent anomalies
    const recentAnomalies = behavior.anomalies.filter(a => 
      a.timestamp > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) && !a.resolved
    );
    
    if (recentAnomalies.length > 0) {
      score -= Math.min(30, recentAnomalies.length * 10);
    }

    return Math.max(this.trustLevels.NONE, Math.min(this.trustLevels.MAXIMUM, score));
  }

  /**
   * Validate network location and context
   */
  async validateNetworkLocation(accessRequest) {
    const { context } = accessRequest;
    const { ipAddress, networkSegment } = context;
    
    if (!ipAddress) {
      return this.trustLevels.LOW;
    }

    let score = this.trustLevels.MEDIUM;

    // Check if IP is from trusted networks
    if (await this.isTrustedNetwork(ipAddress)) {
      score += 25;
    }

    // Check for VPN/Proxy usage
    if (await this.isVpnOrProxy(ipAddress)) {
      score -= 15; // Could be legitimate or suspicious
    }

    // Check threat intelligence
    const threatIntel = await this.checkThreatIntelligence(ipAddress);
    if (threatIntel.isMalicious) {
      score -= 50;
    } else if (threatIntel.isKnownGood) {
      score += 10;
    }

    // Network segment validation
    if (networkSegment && await this.isApprovedNetworkSegment(networkSegment)) {
      score += 15;
    }

    // Geolocation consistency
    const geoIpService = require('./geoIpService');
    const location = geoIpService.lookup(ipAddress);
    
    if (location && await this.isUnusualLocation(accessRequest.userId, location)) {
      score -= 20;
    }

    return Math.max(this.trustLevels.NONE, Math.min(this.trustLevels.MAXIMUM, score));
  }

  /**
   * Validate authentication strength
   */
  async validateAuthenticationStrength(accessRequest) {
    const { userId, context } = accessRequest;
    const { authMethod, mfaUsed, sessionAge } = context;
    
    let score = this.trustLevels.LOW;

    // Multi-factor authentication
    if (mfaUsed) {
      score += 30;
      
      // Additional points for stronger MFA methods
      if (context.mfaMethod === 'hardware_token' || context.mfaMethod === 'biometric') {
        score += 10;
      } else if (context.mfaMethod === 'app_authenticator') {
        score += 5;
      }
    }

    // Authentication method strength
    switch (authMethod) {
      case 'certificate':
        score += 25;
        break;
      case 'saml_sso':
        score += 20;
        break;
      case 'oauth':
        score += 15;
        break;
      case 'password':
        score += 5;
        break;
      default:
        score += 0;
    }

    // Session age factor
    if (sessionAge) {
      const ageInHours = sessionAge / (60 * 60 * 1000);
      if (ageInHours > 8) {
        score -= Math.min(20, Math.floor(ageInHours / 8) * 5);
      }
    }

    // Password strength and age (if password-based)
    if (authMethod === 'password') {
      const User = require('../models/User');
      const user = await User.findById(userId);
      
      if (user && user.lastPasswordChange) {
        const daysSinceChange = (Date.now() - user.lastPasswordChange) / (24 * 60 * 60 * 1000);
        if (daysSinceChange > 90) {
          score -= 10;
        }
      }
    }

    return Math.max(this.trustLevels.NONE, Math.min(this.trustLevels.MAXIMUM, score));
  }

  /**
   * Validate time-based context
   */
  async validateTimeContext(accessRequest) {
    const { userId, context } = accessRequest;
    const { timestamp = new Date() } = context;
    
    let score = this.trustLevels.MEDIUM;
    
    const User = require('../models/User');
    const user = await User.findById(userId);
    
    if (!user) {
      return this.trustLevels.NONE;
    }

    // Business hours check
    const hour = timestamp.getHours();
    const dayOfWeek = timestamp.getDay();
    
    // Assume business hours: Monday-Friday, 8 AM - 6 PM
    const isBusinessHours = (dayOfWeek >= 1 && dayOfWeek <= 5) && (hour >= 8 && hour <= 18);
    
    if (isBusinessHours) {
      score += 15;
    } else {
      score -= 10;
    }

    // User's typical access patterns
    const UserBehavior = require('../models/UserBehavior');
    const behavior = await UserBehavior.findOne({ userId });
    
    if (behavior && behavior.patterns.accessHours) {
      const typicalHours = behavior.patterns.accessHours;
      if (typicalHours.includes(hour)) {
        score += 10;
      } else {
        score -= 5;
      }
    }

    // Rapid successive access attempts
    if (context.recentAccessAttempts > 5) {
      score -= 15;
    }

    return Math.max(this.trustLevels.NONE, Math.min(this.trustLevels.MAXIMUM, score));
  }

  /**
   * Validate resource sensitivity
   */
  async validateResourceSensitivity(accessRequest) {
    const { resource, action } = accessRequest;
    
    let score = this.trustLevels.MEDIUM;
    
    // Get resource classification
    const Resource = require('../models/Resource');
    const resourceDoc = await Resource.findOne({ identifier: resource });
    
    if (!resourceDoc) {
      // Default to medium sensitivity for unknown resources
      return score;
    }

    // Adjust score based on sensitivity level
    switch (resourceDoc.sensitivityLevel) {
      case 'public':
        score += 25;
        break;
      case 'internal':
        score += 10;
        break;
      case 'confidential':
        score -= 10;
        break;
      case 'restricted':
        score -= 25;
        break;
      case 'top_secret':
        score -= 40;
        break;
    }

    // Action-specific adjustments
    const highRiskActions = ['delete', 'modify', 'export', 'share'];
    if (highRiskActions.includes(action.toLowerCase())) {
      score -= 15;
    }

    return Math.max(this.trustLevels.NONE, Math.min(this.trustLevels.MAXIMUM, score));
  }

  /**
   * Make final access decision based on trust score and policies
   */
  makeAccessDecision(trustScore, policyEvaluation) {
    const requiredTrustLevel = policyEvaluation.requiredTrustLevel || this.trustLevels.MEDIUM;
    
    if (trustScore.overall >= requiredTrustLevel) {
      return {
        result: 'allow',
        factors: trustScore.factors,
        confidence: this.calculateConfidence(trustScore, policyEvaluation)
      };
    } else if (trustScore.overall >= requiredTrustLevel - 20) {
      return {
        result: 'conditional',
        factors: trustScore.factors,
        confidence: this.calculateConfidence(trustScore, policyEvaluation)
      };
    } else {
      return {
        result: 'deny',
        factors: trustScore.factors,
        confidence: this.calculateConfidence(trustScore, policyEvaluation)
      };
    }
  }

  /**
   * Get additional requirements for conditional access
   */
  async getAdditionalRequirements(accessRequest, trustScore) {
    const requirements = [];
    
    // Low authentication strength
    if (trustScore.factors.authentication_strength < this.trustLevels.MEDIUM) {
      requirements.push({
        type: 'step_up_auth',
        description: 'Additional authentication required',
        options: ['mfa_challenge', 'certificate_auth']
      });
    }

    // Unknown or untrusted device
    if (trustScore.factors.device_compliance < this.trustLevels.MEDIUM) {
      requirements.push({
        type: 'device_verification',
        description: 'Device compliance verification required',
        options: ['device_registration', 'security_scan']
      });
    }

    // Unusual behavior patterns
    if (trustScore.factors.user_behavior < this.trustLevels.MEDIUM) {
      requirements.push({
        type: 'behavioral_verification',
        description: 'Additional verification due to unusual activity',
        options: ['manager_approval', 'extended_monitoring']
      });
    }

    // Untrusted network location
    if (trustScore.factors.network_location < this.trustLevels.MEDIUM) {
      requirements.push({
        type: 'network_verification',
        description: 'Access from untrusted network location',
        options: ['vpn_required', 'location_approval']
      });
    }

    return requirements;
  }

  /**
   * Initialize default Zero Trust policies
   */
  initializePolicies() {
    // Default policies for different resource types and sensitivity levels
    this.accessPolicies.set('default', {
      requiredTrustLevel: this.trustLevels.MEDIUM,
      allowConditionalAccess: true,
      maxSessionDuration: 8 * 60 * 60 * 1000, // 8 hours
      requireReauth: false
    });

    this.accessPolicies.set('high_sensitivity', {
      requiredTrustLevel: this.trustLevels.HIGH,
      allowConditionalAccess: false,
      maxSessionDuration: 2 * 60 * 60 * 1000, // 2 hours
      requireReauth: true
    });

    this.accessPolicies.set('admin_access', {
      requiredTrustLevel: this.trustLevels.MAXIMUM,
      allowConditionalAccess: false,
      maxSessionDuration: 1 * 60 * 60 * 1000, // 1 hour
      requireReauth: true,
      additionalRequirements: ['manager_approval', 'audit_logging']
    });
  }

  /**
   * Helper methods
   */
  getTrustLevel(score) {
    if (score >= this.trustLevels.MAXIMUM) return 'MAXIMUM';
    if (score >= this.trustLevels.HIGH) return 'HIGH';
    if (score >= this.trustLevels.MEDIUM) return 'MEDIUM';
    if (score >= this.trustLevels.LOW) return 'LOW';
    return 'NONE';
  }

  generateSecureSessionId() {
    return crypto.randomBytes(32).toString('hex');
  }

  getSessionDuration(trustScore) {
    // Higher trust = longer sessions
    const baseDuration = 2 * 60 * 60 * 1000; // 2 hours
    const multiplier = Math.max(0.5, trustScore.overall / 100);
    return Math.floor(baseDuration * multiplier);
  }

  calculateConfidence(trustScore, policyEvaluation) {
    // Calculate confidence based on data quality and consistency
    const factorCount = Object.keys(trustScore.factors).length;
    const expectedFactors = this.trustFactors.size;
    const completeness = factorCount / expectedFactors;
    
    const variance = this.calculateVariance(Object.values(trustScore.factors));
    const consistency = Math.max(0, 1 - (variance / 100));
    
    return Math.round((completeness * 0.6 + consistency * 0.4) * 100);
  }

  calculateVariance(scores) {
    const mean = scores.reduce((sum, score) => sum + score, 0) / scores.length;
    const squaredDiffs = scores.map(score => Math.pow(score - mean, 2));
    return squaredDiffs.reduce((sum, diff) => sum + diff, 0) / scores.length;
  }

  // Placeholder methods for external integrations
  async getApplicablePolicies(resource, action) {
    return { requiredTrustLevel: this.trustLevels.MEDIUM, appliedPolicies: ['default'] };
  }
  
  async evaluatePolicies(policies, accessRequest, trustScore) {
    return { requiredTrustLevel: this.trustLevels.MEDIUM, appliedPolicies: ['default'] };
  }
  
  async logAccessDecision(accessRequest, trustScore, decision) {
    logger.info(`Zero Trust decision: ${decision.result} (score: ${trustScore.overall})`);
  }
  
  async isTrustedNetwork(ipAddress) { return false; }
  async isVpnOrProxy(ipAddress) { return false; }
  async checkThreatIntelligence(ipAddress) { return { isMalicious: false, isKnownGood: false }; }
  async isApprovedNetworkSegment(segment) { return true; }
  async isUnusualLocation(userId, location) { return false; }
  async validateDeviceCertificate(certificate) { return true; }
  
  isRecentPatchLevel(patchLevel) {
    // Simplified - should check against actual patch database
    return true;
  }
  
  isKnownLocation(current, knownLocations) {
    return knownLocations.some(known => 
      known.country === current.country && known.city === current.city
    );
  }
}

module.exports = new ZeroTrustService();