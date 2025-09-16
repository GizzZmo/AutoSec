/**
 * Real-time Risk Scoring and Threat Prioritization Service
 * Provides dynamic risk assessment and threat priority scoring
 */

const logger = require('../config/logger');
const UserBehavior = require('../models/UserBehavior');
const NetworkBehavior = require('../models/NetworkBehavior');
const ThreatEvent = require('../models/ThreatEvent');

class RiskScoringService {
  constructor() {
    this.riskFactors = this.initializeRiskFactors();
    this.threatPriorityWeights = this.initializeThreatPriorityWeights();
    this.riskCache = new Map(); // In production, use Redis
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Initialize risk factor configurations
   */
  initializeRiskFactors() {
    return {
      user: {
        behavioral_anomaly: { weight: 0.3, max_score: 40 },
        role_privilege: { weight: 0.2, max_score: 30 },
        access_pattern: { weight: 0.15, max_score: 20 },
        location_change: { weight: 0.15, max_score: 20 },
        device_change: { weight: 0.1, max_score: 15 },
        time_anomaly: { weight: 0.1, max_score: 15 },
      },
      network: {
        traffic_anomaly: { weight: 0.25, max_score: 35 },
        destination_anomaly: { weight: 0.2, max_score: 30 },
        protocol_anomaly: { weight: 0.15, max_score: 25 },
        volume_spike: { weight: 0.15, max_score: 25 },
        geolocation_risk: { weight: 0.15, max_score: 20 },
        port_scanning: { weight: 0.1, max_score: 15 },
      },
      system: {
        vulnerability_exposure: { weight: 0.3, max_score: 40 },
        patch_level: { weight: 0.2, max_score: 30 },
        configuration_drift: { weight: 0.2, max_score: 25 },
        access_controls: { weight: 0.15, max_score: 20 },
        monitoring_coverage: { weight: 0.15, max_score: 15 },
      },
    };
  }

  /**
   * Initialize threat priority weights
   */
  initializeThreatPriorityWeights() {
    return {
      impact: 0.3,
      likelihood: 0.25,
      velocity: 0.2,
      confidence: 0.15,
      context: 0.1,
    };
  }

  /**
   * Calculate comprehensive risk score for a user
   * @param {string} userId - User ID
   * @param {Object} context - Additional context information
   * @returns {Object} Risk assessment
   */
  async calculateUserRiskScore(userId, context = {}) {
    try {
      // Check cache first
      const cacheKey = `user_risk_${userId}`;
      const cached = this.riskCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.risk;
      }

      logger.info(`Calculating risk score for user: ${userId}`);

      // Get user behavioral data
      const behaviorProfile = await this.getUserBehaviorProfile(userId);
      
      // Get user threat events
      const threatEvents = await this.getUserThreatEvents(userId);

      // Calculate risk factors
      const riskFactors = this.calculateUserRiskFactors(behaviorProfile, threatEvents, context);

      // Calculate overall risk score
      const riskScore = this.aggregateRiskScore(riskFactors, 'user');

      // Determine risk level and recommendations
      const riskLevel = this.determineRiskLevel(riskScore.overall);
      const recommendations = this.generateRiskRecommendations(riskFactors, riskLevel, 'user');

      // Create risk assessment
      const riskAssessment = {
        userId,
        overall: riskScore.overall,
        level: riskLevel,
        factors: riskFactors,
        breakdown: riskScore.breakdown,
        recommendations,
        confidence: this.calculateConfidence(behaviorProfile, threatEvents),
        lastUpdated: new Date(),
        validUntil: new Date(Date.now() + this.cacheTimeout),
      };

      // Cache the result
      this.riskCache.set(cacheKey, {
        risk: riskAssessment,
        timestamp: Date.now(),
      });

      logger.info(`Risk score calculated for user: ${userId}`, {
        riskScore: riskScore.overall,
        riskLevel,
      });

      return riskAssessment;
    } catch (error) {
      logger.error('Error calculating user risk score:', error);
      throw error;
    }
  }

  /**
   * Calculate comprehensive risk score for a network entity
   * @param {string} identifier - Network identifier
   * @param {string} identifierType - Type of identifier
   * @param {Object} context - Additional context information
   * @returns {Object} Risk assessment
   */
  async calculateNetworkRiskScore(identifier, identifierType, context = {}) {
    try {
      const cacheKey = `network_risk_${identifierType}_${identifier}`;
      const cached = this.riskCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.risk;
      }

      logger.info(`Calculating network risk score for: ${identifier}`);

      // Get network behavioral data
      const behaviorProfile = await this.getNetworkBehaviorProfile(identifier, identifierType);
      
      // Get network threat events
      const threatEvents = await this.getNetworkThreatEvents(identifier);

      // Calculate risk factors
      const riskFactors = this.calculateNetworkRiskFactors(behaviorProfile, threatEvents, context);

      // Calculate overall risk score
      const riskScore = this.aggregateRiskScore(riskFactors, 'network');

      // Determine risk level and recommendations
      const riskLevel = this.determineRiskLevel(riskScore.overall);
      const recommendations = this.generateRiskRecommendations(riskFactors, riskLevel, 'network');

      const riskAssessment = {
        identifier,
        identifierType,
        overall: riskScore.overall,
        level: riskLevel,
        factors: riskFactors,
        breakdown: riskScore.breakdown,
        recommendations,
        confidence: this.calculateConfidence(behaviorProfile, threatEvents),
        lastUpdated: new Date(),
        validUntil: new Date(Date.now() + this.cacheTimeout),
      };

      this.riskCache.set(cacheKey, {
        risk: riskAssessment,
        timestamp: Date.now(),
      });

      logger.info(`Network risk score calculated for: ${identifier}`, {
        riskScore: riskScore.overall,
        riskLevel,
      });

      return riskAssessment;
    } catch (error) {
      logger.error('Error calculating network risk score:', error);
      throw error;
    }
  }

  /**
   * Prioritize threats based on multiple factors
   * @param {Array} threats - Array of threat events
   * @returns {Array} Prioritized threats with scores
   */
  prioritizeThreats(threats) {
    try {
      const prioritizedThreats = threats.map(threat => {
        const priorityScore = this.calculateThreatPriority(threat);
        return {
          ...threat.toObject(),
          priorityScore,
          priorityLevel: this.determinePriorityLevel(priorityScore),
        };
      });

      // Sort by priority score (highest first)
      prioritizedThreats.sort((a, b) => b.priorityScore - a.priorityScore);

      logger.info(`Prioritized ${threats.length} threats`);
      return prioritizedThreats;
    } catch (error) {
      logger.error('Error prioritizing threats:', error);
      return threats;
    }
  }

  /**
   * Calculate real-time threat priority score
   * @param {Object} threat - Threat event
   * @returns {number} Priority score (0-100)
   */
  calculateThreatPriority(threat) {
    try {
      const factors = {
        impact: this.assessThreatImpact(threat),
        likelihood: this.assessThreatLikelihood(threat),
        velocity: this.assessThreatVelocity(threat),
        confidence: this.assessThreatConfidence(threat),
        context: this.assessThreatContext(threat),
      };

      // Weighted average
      const priorityScore = Object.entries(this.threatPriorityWeights).reduce(
        (total, [factor, weight]) => total + (factors[factor] * weight * 100),
        0
      );

      return Math.min(100, Math.max(0, Math.round(priorityScore)));
    } catch (error) {
      logger.error('Error calculating threat priority:', error);
      return 50; // Default medium priority
    }
  }

  /**
   * Calculate user risk factors
   */
  calculateUserRiskFactors(behaviorProfile, threatEvents, context) {
    const factors = {};

    if (behaviorProfile) {
      // Behavioral anomaly factor
      const anomalies = behaviorProfile.anomalies || [];
      const highSeverityAnomalies = anomalies.filter(a => 
        a.severity === 'high' || a.severity === 'critical'
      );
      factors.behavioral_anomaly = Math.min(1, highSeverityAnomalies.length / 3);

      // Role privilege factor
      const userRole = context.userRole || 'viewer';
      const roleRiskMap = { admin: 0.9, analyst: 0.7, operator: 0.5, viewer: 0.2 };
      factors.role_privilege = roleRiskMap[userRole] || 0.5;

      // Access pattern factor
      const activityRisk = (behaviorProfile.riskScores?.activityRisk || 0) / 100;
      factors.access_pattern = activityRisk;

      // Location change factor
      const locationRisk = (behaviorProfile.riskScores?.locationRisk || 0) / 100;
      factors.location_change = locationRisk;

      // Device change factor
      const deviceRisk = (behaviorProfile.riskScores?.deviceRisk || 0) / 100;
      factors.device_change = deviceRisk;

      // Time anomaly factor
      const loginRisk = (behaviorProfile.riskScores?.loginRisk || 0) / 100;
      factors.time_anomaly = loginRisk;
    }

    return factors;
  }

  /**
   * Calculate network risk factors
   */
  calculateNetworkRiskFactors(behaviorProfile, threatEvents, context) {
    const factors = {};

    if (behaviorProfile) {
      // Traffic anomaly factor
      const trafficRisk = (behaviorProfile.riskScores?.trafficRisk || 0) / 100;
      factors.traffic_anomaly = trafficRisk;

      // Destination anomaly factor
      const connectionRisk = (behaviorProfile.riskScores?.connectionRisk || 0) / 100;
      factors.destination_anomaly = connectionRisk;

      // Protocol anomaly factor
      const protocols = behaviorProfile.trafficPatterns?.protocols || [];
      const suspiciousProtocols = protocols.filter(p => 
        ['tor', 'i2p', 'bittorrent'].includes(p.protocol.toLowerCase())
      );
      factors.protocol_anomaly = Math.min(1, suspiciousProtocols.length / protocols.length);

      // Volume spike factor
      const avgBytes = behaviorProfile.trafficPatterns?.averageBytesPerSecond || 0;
      factors.volume_spike = Math.min(1, avgBytes / 10000000); // Normalize to 10MB/s

      // Geolocation risk factor
      const geoRisk = (behaviorProfile.riskScores?.geoRisk || 0) / 100;
      factors.geolocation_risk = geoRisk;

      // Port scanning factor
      const ports = behaviorProfile.trafficPatterns?.ports || [];
      factors.port_scanning = Math.min(1, ports.length / 100); // Normalize to 100 ports
    }

    return factors;
  }

  /**
   * Aggregate risk score from factors
   */
  aggregateRiskScore(factors, entityType) {
    const entityFactors = this.riskFactors[entityType] || {};
    let totalScore = 0;
    let totalWeight = 0;
    const breakdown = {};

    Object.entries(factors).forEach(([factorName, factorValue]) => {
      const factorConfig = entityFactors[factorName];
      if (factorConfig) {
        const factorScore = factorValue * factorConfig.max_score;
        const weightedScore = factorScore * factorConfig.weight;
        
        totalScore += weightedScore;
        totalWeight += factorConfig.weight;
        
        breakdown[factorName] = {
          value: factorValue,
          score: factorScore,
          weight: factorConfig.weight,
          weighted_score: weightedScore,
        };
      }
    });

    const overall = totalWeight > 0 ? Math.round(totalScore / totalWeight) : 0;

    return {
      overall: Math.min(100, Math.max(0, overall)),
      breakdown,
    };
  }

  /**
   * Assess threat impact
   */
  assessThreatImpact(threat) {
    const severityMap = {
      critical: 1.0,
      high: 0.8,
      medium: 0.5,
      low: 0.2,
    };

    let impact = severityMap[threat.severity] || 0.5;

    // Adjust based on affected entities
    if (threat.entities) {
      if (threat.entities.users?.length > 0) {
        impact += 0.1;
      }
      if (threat.entities.networks?.length > 0) {
        impact += 0.1;
      }
      if (threat.entities.systems?.length > 0) {
        impact += 0.15;
      }
    }

    return Math.min(1, impact);
  }

  /**
   * Assess threat likelihood
   */
  assessThreatLikelihood(threat) {
    let likelihood = 0.5; // Default medium likelihood

    // Based on confidence level
    if (threat.confidence && threat.confidence > 0.8) {
      likelihood += 0.3;
    } else if (threat.confidence && threat.confidence > 0.6) {
      likelihood += 0.2;
    }

    // Based on evidence quality
    if (threat.evidence && Object.keys(threat.evidence).length > 2) {
      likelihood += 0.2;
    }

    // Based on risk score
    if (threat.riskScore > 80) {
      likelihood += 0.3;
    } else if (threat.riskScore > 60) {
      likelihood += 0.2;
    }

    return Math.min(1, likelihood);
  }

  /**
   * Assess threat velocity (urgency)
   */
  assessThreatVelocity(threat) {
    const now = new Date();
    const created = new Date(threat.createdAt);
    const ageMinutes = (now - created) / (1000 * 60);

    // Recent threats have higher velocity
    if (ageMinutes < 5) return 1.0;
    if (ageMinutes < 15) return 0.8;
    if (ageMinutes < 60) return 0.6;
    if (ageMinutes < 240) return 0.4;
    return 0.2;
  }

  /**
   * Assess threat confidence
   */
  assessThreatConfidence(threat) {
    return threat.confidence || 0.5;
  }

  /**
   * Assess threat context
   */
  assessThreatContext(threat) {
    let context = 0.5;

    // Business hours adjustment
    const hour = new Date().getHours();
    if (hour >= 9 && hour <= 17) {
      context += 0.2; // Higher priority during business hours
    }

    // Tag-based adjustments
    if (threat.tags) {
      if (threat.tags.includes('automated-attack')) context += 0.2;
      if (threat.tags.includes('data-exfiltration')) context += 0.3;
      if (threat.tags.includes('privilege-escalation')) context += 0.25;
    }

    return Math.min(1, context);
  }

  /**
   * Determine risk level from score
   */
  determineRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
  }

  /**
   * Determine priority level from score
   */
  determinePriorityLevel(score) {
    if (score >= 80) return 'urgent';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
  }

  /**
   * Generate risk recommendations
   */
  generateRiskRecommendations(factors, riskLevel, entityType) {
    const recommendations = [];

    if (riskLevel === 'critical' || riskLevel === 'high') {
      recommendations.push({
        priority: 'immediate',
        action: 'Enable enhanced monitoring',
        description: 'Increase monitoring frequency and alert sensitivity',
      });

      if (entityType === 'user') {
        recommendations.push({
          priority: 'immediate',
          action: 'Require additional authentication',
          description: 'Enforce MFA and additional verification steps',
        });
      }

      if (entityType === 'network') {
        recommendations.push({
          priority: 'immediate',
          action: 'Implement traffic restrictions',
          description: 'Apply network segmentation and traffic filtering',
        });
      }
    }

    // Factor-specific recommendations
    Object.entries(factors).forEach(([factor, value]) => {
      if (value > 0.7) {
        recommendations.push(this.getFactorRecommendation(factor, entityType));
      }
    });

    return recommendations.filter(r => r); // Remove null recommendations
  }

  /**
   * Get factor-specific recommendation
   */
  getFactorRecommendation(factor, entityType) {
    const recommendations = {
      user: {
        behavioral_anomaly: {
          priority: 'high',
          action: 'Review user activity',
          description: 'Investigate unusual behavior patterns and verify user identity',
        },
        location_change: {
          priority: 'medium',
          action: 'Verify location',
          description: 'Confirm user location and investigate any suspicious access',
        },
        device_change: {
          priority: 'medium',
          action: 'Verify device',
          description: 'Confirm new device registration and access patterns',
        },
      },
      network: {
        traffic_anomaly: {
          priority: 'high',
          action: 'Investigate traffic patterns',
          description: 'Analyze unusual traffic and potential data exfiltration',
        },
        port_scanning: {
          priority: 'high',
          action: 'Block scanning activity',
          description: 'Implement blocking rules for port scanning behavior',
        },
      },
    };

    return recommendations[entityType]?.[factor] || null;
  }

  /**
   * Calculate confidence level
   */
  calculateConfidence(behaviorProfile, threatEvents) {
    let confidence = 0.5; // Base confidence

    if (behaviorProfile) {
      // More data points increase confidence
      const dataPoints = (behaviorProfile.loginPatterns?.geolocations?.length || 0) +
                        (behaviorProfile.activityPatterns?.commonActions?.length || 0);
      confidence += Math.min(0.3, dataPoints / 50);
    }

    if (threatEvents.length > 0) {
      // Recent threat events increase confidence
      const recentEvents = threatEvents.filter(event => 
        new Date() - new Date(event.createdAt) < 24 * 60 * 60 * 1000
      );
      confidence += Math.min(0.2, recentEvents.length / 10);
    }

    return Math.min(1, confidence);
  }

  /**
   * Helper methods to get data
   */
  async getUserBehaviorProfile(userId) {
    try {
      return await UserBehavior.findOne({ userId }).sort({ lastUpdated: -1 });
    } catch (error) {
      logger.error('Error getting user behavior profile:', error);
      return null;
    }
  }

  async getNetworkBehaviorProfile(identifier, identifierType) {
    try {
      return await NetworkBehavior.findOne({ identifier, identifierType })
        .sort({ lastUpdated: -1 });
    } catch (error) {
      logger.error('Error getting network behavior profile:', error);
      return null;
    }
  }

  async getUserThreatEvents(userId) {
    try {
      return await ThreatEvent.find({
        'entities.users.userId': userId,
        status: { $in: ['new', 'investigating', 'confirmed'] },
      }).sort({ createdAt: -1 }).limit(10);
    } catch (error) {
      logger.error('Error getting user threat events:', error);
      return [];
    }
  }

  async getNetworkThreatEvents(identifier) {
    try {
      return await ThreatEvent.find({
        $or: [
          { 'entities.networks.ipAddress': identifier },
          { 'entities.networks.subnet': identifier },
        ],
        status: { $in: ['new', 'investigating', 'confirmed'] },
      }).sort({ createdAt: -1 }).limit(10);
    } catch (error) {
      logger.error('Error getting network threat events:', error);
      return [];
    }
  }

  /**
   * Clear risk cache (for testing or manual refresh)
   */
  clearCache() {
    this.riskCache.clear();
    logger.info('Risk cache cleared');
  }
}

module.exports = new RiskScoringService();