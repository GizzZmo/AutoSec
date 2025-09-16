const UserBehavior = require('../models/UserBehavior');
const ThreatEvent = require('../models/ThreatEvent');
const Log = require('../models/Log');
const mlService = require('./mlBehaviorAnalysisService');
const logger = require('../config/logger');
const crypto = require('crypto');

class UserBehaviorAnalyzer {
  constructor() {
    this.profileWindow = 30; // days
    this.anomalyThresholds = {
      loginTimeDeviation: 2, // standard deviations
      locationChange: 1000, // km
      activitySpike: 3, // times normal activity
      newDeviceRisk: 0.7, // risk score threshold
    };
  }

  /**
   * Analyze user behavior and update profile
   * @param {string} userId - User ID to analyze
   * @param {Date} endDate - End date for analysis period
   */
  async analyzeUserBehavior(userId, endDate = new Date()) {
    try {
      const startDate = new Date(endDate.getTime() - (this.profileWindow * 24 * 60 * 60 * 1000));
      
      logger.info(`Analyzing user behavior for user ${userId}`, {
        userId,
        startDate,
        endDate,
      });

      // Fetch user logs for the analysis period
      const userLogs = await Log.find({
        user_id: userId,
        timestamp: { $gte: startDate, $lte: endDate },
      }).sort({ timestamp: 1 });

      if (userLogs.length === 0) {
        logger.warn(`No logs found for user ${userId} in the analysis period`);
        return null;
      }

      // Analyze login patterns
      const loginPatterns = this.analyzeLoginPatterns(userLogs);
      
      // Analyze activity patterns
      const activityPatterns = this.analyzeActivityPatterns(userLogs);
      
      // Calculate risk scores
      const riskScores = this.calculateRiskScores(loginPatterns, activityPatterns, userLogs);
      
      // Detect anomalies
      const anomalies = await this.detectAnomalies(userId, loginPatterns, activityPatterns, userLogs);

      // Create or update user behavior profile
      const behaviorProfile = await UserBehavior.findOneAndUpdate(
        { userId, 'profilePeriod.endDate': endDate },
        {
          userId,
          username: userLogs[0].metadata?.username || 'unknown',
          profilePeriod: { startDate, endDate },
          loginPatterns,
          activityPatterns,
          riskScores,
          anomalies,
          lastUpdated: new Date(),
        },
        { upsert: true, new: true }
      );

      // Generate threat events for high-risk anomalies
      await this.generateThreatEvents(behaviorProfile);

      // Enhanced ML analysis
      const mlAnalysis = await mlService.analyzeUserBehavior({
        loginPatterns,
        activityPatterns,
        riskScores,
        anomalies,
      }, userId);

      // Update behavior profile with ML insights
      behaviorProfile.mlAnalysis = mlAnalysis.analysis;
      await behaviorProfile.save();

      logger.info(`User behavior analysis completed for user ${userId}`, {
        userId,
        riskScore: riskScores.overall,
        anomaliesCount: anomalies.length,
        mlRiskScore: mlAnalysis.analysis.riskScore.overall,
      });

      return {
        behaviorProfile,
        mlAnalysis,
      };
    } catch (error) {
      logger.error('Error analyzing user behavior:', error);
      throw error;
    }
  }

  /**
   * Analyze login patterns from user logs
   */
  analyzeLoginPatterns(logs) {
    const loginLogs = logs.filter(log => 
      log.event_type === 'login' || 
      log.event_type === 'authentication' ||
      log.message.toLowerCase().includes('login')
    );

    if (loginLogs.length === 0) {
      return this.getDefaultLoginPatterns();
    }

    // Calculate login frequency
    const totalDays = Math.max(1, (new Date() - new Date(logs[0].timestamp)) / (24 * 60 * 60 * 1000));
    const averageLoginsPerDay = loginLogs.length / totalDays;

    // Analyze login hours
    const hourFrequency = {};
    const dayFrequency = {};
    const geolocations = {};
    const devices = {};
    const ipAddresses = {};

    let totalSessionDuration = 0;
    let sessionCount = 0;

    loginLogs.forEach(log => {
      const date = new Date(log.timestamp);
      const hour = date.getHours();
      const dayOfWeek = date.getDay();

      // Count hour frequency
      hourFrequency[hour] = (hourFrequency[hour] || 0) + 1;
      
      // Count day frequency
      dayFrequency[dayOfWeek] = (dayFrequency[dayOfWeek] || 0) + 1;

      // Geolocation analysis
      if (log.country) {
        const geoKey = `${log.country}-${log.region || 'unknown'}-${log.city || 'unknown'}`;
        if (!geolocations[geoKey]) {
          geolocations[geoKey] = {
            country: log.country,
            region: log.region,
            city: log.city,
            frequency: 0,
            lastSeen: log.timestamp,
          };
        }
        geolocations[geoKey].frequency += 1;
        if (log.timestamp > geolocations[geoKey].lastSeen) {
          geolocations[geoKey].lastSeen = log.timestamp;
        }
      }

      // Device analysis
      if (log.metadata?.userAgent) {
        const deviceFingerprint = crypto.createHash('md5')
          .update(log.metadata.userAgent)
          .digest('hex');
        
        if (!devices[deviceFingerprint]) {
          devices[deviceFingerprint] = {
            userAgent: log.metadata.userAgent,
            deviceFingerprint,
            frequency: 0,
            lastSeen: log.timestamp,
          };
        }
        devices[deviceFingerprint].frequency += 1;
        if (log.timestamp > devices[deviceFingerprint].lastSeen) {
          devices[deviceFingerprint].lastSeen = log.timestamp;
        }
      }

      // IP address analysis
      if (log.ip_address) {
        if (!ipAddresses[log.ip_address]) {
          ipAddresses[log.ip_address] = {
            ip: log.ip_address,
            frequency: 0,
            lastSeen: log.timestamp,
          };
        }
        ipAddresses[log.ip_address].frequency += 1;
        if (log.timestamp > ipAddresses[log.ip_address].lastSeen) {
          ipAddresses[log.ip_address].lastSeen = log.timestamp;
        }
      }

      // Session duration (simplified - based on consecutive logs)
      if (log.metadata?.sessionDuration) {
        totalSessionDuration += log.metadata.sessionDuration;
        sessionCount += 1;
      }
    });

    const averageSessionDuration = sessionCount > 0 ? totalSessionDuration / sessionCount : 30; // default 30 minutes

    return {
      averageLoginsPerDay,
      commonLoginHours: Object.entries(hourFrequency)
        .map(([hour, frequency]) => ({ hour: parseInt(hour), frequency }))
        .sort((a, b) => b.frequency - a.frequency),
      commonLoginDays: Object.entries(dayFrequency)
        .map(([dayOfWeek, frequency]) => ({ dayOfWeek: parseInt(dayOfWeek), frequency }))
        .sort((a, b) => b.frequency - a.frequency),
      averageSessionDuration,
      geolocations: Object.values(geolocations),
      devices: Object.values(devices),
      ipAddresses: Object.values(ipAddresses),
    };
  }

  /**
   * Analyze activity patterns from user logs
   */
  analyzeActivityPatterns(logs) {
    const actionFrequency = {};
    const dataAccess = {};
    const fileOperations = {
      downloads: 0,
      uploads: 0,
      modifications: 0,
    };

    let totalActions = 0;
    let totalSessions = 1; // At least one session

    logs.forEach(log => {
      // Count actions
      const action = log.event_type || 'unknown';
      actionFrequency[action] = (actionFrequency[action] || 0) + 1;
      totalActions += 1;

      // Data access patterns
      if (log.metadata?.resource) {
        const resource = log.metadata.resource;
        if (!dataAccess[resource]) {
          dataAccess[resource] = {
            resource,
            frequency: 0,
            lastAccessed: log.timestamp,
          };
        }
        dataAccess[resource].frequency += 1;
        if (log.timestamp > dataAccess[resource].lastAccessed) {
          dataAccess[resource].lastAccessed = log.timestamp;
        }
      }

      // File operations
      if (log.event_type === 'file_download') {
        fileOperations.downloads += 1;
      } else if (log.event_type === 'file_upload') {
        fileOperations.uploads += 1;
      } else if (log.event_type === 'file_modification') {
        fileOperations.modifications += 1;
      }
    });

    return {
      averageActionsPerSession: totalActions / totalSessions,
      commonActions: Object.entries(actionFrequency)
        .map(([action, frequency]) => ({ action, frequency }))
        .sort((a, b) => b.frequency - a.frequency),
      dataAccess: Object.values(dataAccess),
      fileOperations,
    };
  }

  /**
   * Calculate risk scores based on patterns and logs
   */
  calculateRiskScores(loginPatterns, activityPatterns, logs) {
    let loginRisk = 0;
    let activityRisk = 0;
    let deviceRisk = 0;
    let locationRisk = 0;

    // Login risk factors
    if (loginPatterns.averageLoginsPerDay > 20) {
      loginRisk += 30; // High login frequency
    }
    if (loginPatterns.geolocations.length > 5) {
      locationRisk += 40; // Multiple locations
    }
    if (loginPatterns.devices.length > 3) {
      deviceRisk += 35; // Multiple devices
    }

    // Activity risk factors
    if (activityPatterns.averageActionsPerSession > 100) {
      activityRisk += 25; // High activity
    }
    if (activityPatterns.fileOperations.downloads > 50) {
      activityRisk += 30; // High download activity
    }

    // Check for suspicious patterns in logs
    const suspiciousLogs = logs.filter(log => 
      log.level === 'error' || 
      log.level === 'critical' ||
      log.message.toLowerCase().includes('suspicious') ||
      log.message.toLowerCase().includes('failed') ||
      log.message.toLowerCase().includes('unauthorized')
    );

    if (suspiciousLogs.length > logs.length * 0.1) {
      activityRisk += 40; // High error rate
    }

    // Normalize risk scores (0-100)
    loginRisk = Math.min(100, loginRisk);
    activityRisk = Math.min(100, activityRisk);
    deviceRisk = Math.min(100, deviceRisk);
    locationRisk = Math.min(100, locationRisk);

    const overall = Math.round((loginRisk + activityRisk + deviceRisk + locationRisk) / 4);

    return {
      overall,
      loginRisk,
      activityRisk,
      deviceRisk,
      locationRisk,
    };
  }

  /**
   * Detect anomalies in user behavior
   */
  async detectAnomalies(userId, loginPatterns, activityPatterns, logs) {
    const anomalies = [];

    try {
      // Get historical behavior for comparison
      const historicalProfiles = await UserBehavior.find({
        userId,
        'profilePeriod.endDate': { $lt: new Date() },
      }).sort({ 'profilePeriod.endDate': -1 }).limit(5);

      if (historicalProfiles.length === 0) {
        logger.info(`No historical data for user ${userId}, skipping anomaly detection`);
        return anomalies;
      }

      // Calculate baseline from historical profiles
      const baseline = this.calculateBaseline(historicalProfiles);

      // Check for login time anomalies
      const currentLoginHours = loginPatterns.commonLoginHours;
      const baselineLoginHours = baseline.loginHours || [];
      
      if (this.isLoginTimeAnomaly(currentLoginHours, baselineLoginHours)) {
        anomalies.push({
          type: 'login_time',
          severity: 'medium',
          description: 'User logging in at unusual times',
          riskScore: 60,
        });
      }

      // Check for location anomalies
      const currentLocations = loginPatterns.geolocations;
      const baselineLocations = baseline.locations || [];
      
      if (this.isLocationAnomaly(currentLocations, baselineLocations)) {
        anomalies.push({
          type: 'login_location',
          severity: 'high',
          description: 'User logging in from new or unusual locations',
          riskScore: 75,
        });
      }

      // Check for device anomalies
      const currentDevices = loginPatterns.devices;
      const baselineDevices = baseline.devices || [];
      
      if (this.isDeviceAnomaly(currentDevices, baselineDevices)) {
        anomalies.push({
          type: 'device_change',
          severity: 'medium',
          description: 'User accessing from new or unusual devices',
          riskScore: 65,
        });
      }

      // Check for activity spikes
      const currentActivity = activityPatterns.averageActionsPerSession;
      const baselineActivity = baseline.averageActionsPerSession || 10;
      
      if (currentActivity > baselineActivity * this.anomalyThresholds.activitySpike) {
        anomalies.push({
          type: 'activity_spike',
          severity: 'high',
          description: `Activity level ${Math.round(currentActivity / baselineActivity)}x higher than normal`,
          riskScore: 80,
        });
      }

      logger.info(`Detected ${anomalies.length} anomalies for user ${userId}`);
      
      return anomalies;
    } catch (error) {
      logger.error('Error detecting anomalies:', error);
      return anomalies;
    }
  }

  /**
   * Generate threat events for high-risk anomalies
   */
  async generateThreatEvents(behaviorProfile) {
    const highRiskAnomalies = behaviorProfile.anomalies.filter(
      anomaly => anomaly.severity === 'high' || anomaly.severity === 'critical'
    );

    for (const anomaly of highRiskAnomalies) {
      const eventId = `ueba-${behaviorProfile.userId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const threatEvent = new ThreatEvent({
        eventId,
        eventType: 'behavioral_deviation',
        severity: anomaly.severity,
        title: `User Behavioral Anomaly: ${anomaly.type.replace('_', ' ').toUpperCase()}`,
        description: anomaly.description,
        source: {
          system: 'ueba',
          detector: 'UserBehaviorAnalyzer',
          version: '1.0.0',
        },
        entities: {
          users: [{
            userId: behaviorProfile.userId,
            username: behaviorProfile.username,
          }],
        },
        evidence: {
          behavior: {
            observed: {
              riskScore: behaviorProfile.riskScores.overall,
              anomalyType: anomaly.type,
            },
          },
        },
        riskScore: anomaly.riskScore,
        status: 'new',
        tags: ['ueba', 'behavioral-anomaly', anomaly.type],
        metadata: {
          ttl: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days TTL
          retention: 90,
        },
      });

      try {
        await threatEvent.save();
        logger.info(`Generated threat event ${eventId} for user behavioral anomaly`, {
          userId: behaviorProfile.userId,
          anomalyType: anomaly.type,
          severity: anomaly.severity,
        });
      } catch (error) {
        logger.error('Error generating threat event:', error);
      }
    }
  }

  /**
   * Helper methods for anomaly detection
   */
  calculateBaseline(historicalProfiles) {
    // Simplified baseline calculation - in production, use more sophisticated statistical methods
    const loginHours = [];
    const locations = [];
    const devices = [];
    let totalActivity = 0;

    historicalProfiles.forEach(profile => {
      if (profile.loginPatterns) {
        loginHours.push(...(profile.loginPatterns.commonLoginHours || []));
        locations.push(...(profile.loginPatterns.geolocations || []));
        devices.push(...(profile.loginPatterns.devices || []));
      }
      if (profile.activityPatterns) {
        totalActivity += profile.activityPatterns.averageActionsPerSession || 0;
      }
    });

    return {
      loginHours,
      locations,
      devices,
      averageActionsPerSession: totalActivity / historicalProfiles.length,
    };
  }

  isLoginTimeAnomaly(current, baseline) {
    // Check if user is logging in at completely new hours
    const currentHours = new Set(current.map(h => h.hour));
    const baselineHours = new Set(baseline.map(h => h.hour));
    const newHours = [...currentHours].filter(h => !baselineHours.has(h));
    
    return newHours.length > 0 && current.length > 0;
  }

  isLocationAnomaly(current, baseline) {
    // Check for new countries or significant location changes
    const currentCountries = new Set(current.map(l => l.country));
    const baselineCountries = new Set(baseline.map(l => l.country));
    const newCountries = [...currentCountries].filter(c => !baselineCountries.has(c));
    
    return newCountries.length > 0;
  }

  isDeviceAnomaly(current, baseline) {
    // Check for new device fingerprints
    const currentFingerprints = new Set(current.map(d => d.deviceFingerprint));
    const baselineFingerprints = new Set(baseline.map(d => d.deviceFingerprint));
    const newDevices = [...currentFingerprints].filter(f => !baselineFingerprints.has(f));
    
    return newDevices.length > 0;
  }

  getDefaultLoginPatterns() {
    return {
      averageLoginsPerDay: 0,
      commonLoginHours: [],
      commonLoginDays: [],
      averageSessionDuration: 30,
      geolocations: [],
      devices: [],
      ipAddresses: [],
    };
  }
}

module.exports = UserBehaviorAnalyzer;