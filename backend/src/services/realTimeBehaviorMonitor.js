/**
 * Real-time Behavioral Monitoring Service
 * Provides continuous monitoring and analysis of user and network behavior
 */

const EventEmitter = require('events');
const cron = require('node-cron');
const logger = require('../config/logger');
const UserBehaviorAnalyzer = require('./behaviorAnalysis');
const NetworkBehaviorAnalyzer = require('./networkBehaviorAnalysis');
const riskScoringService = require('./riskScoringService');
const rabbitmqConsumer = require('./rabbitmqConsumer');

class RealTimeBehaviorMonitor extends EventEmitter {
  constructor() {
    super();
    this.isMonitoring = false;
    this.monitoringIntervals = new Map();
    this.behaviorCache = new Map();
    this.alertThresholds = this.initializeAlertThresholds();
    this.analysisTasks = new Map();
    
    // Initialize analyzers
    this.userAnalyzer = new UserBehaviorAnalyzer();
    this.networkAnalyzer = new NetworkBehaviorAnalyzer();
  }

  /**
   * Initialize alert thresholds for real-time monitoring
   */
  initializeAlertThresholds() {
    return {
      user: {
        riskScore: 70,
        anomalyCount: 3,
        highSeverityAnomalies: 1,
        consecutiveFailedLogins: 5,
        unusualLocationAccess: true,
        newDeviceAccess: true,
      },
      network: {
        riskScore: 75,
        trafficSpike: 5.0, // times normal
        newDestinations: 10,
        portScanThreshold: 20,
        suspiciousProtocols: true,
        malwareIndicators: true,
      },
      system: {
        responseTime: 30000, // 30 seconds
        batchSize: 100,
        maxConcurrentAnalysis: 10,
      },
    };
  }

  /**
   * Start real-time behavioral monitoring
   */
  async startMonitoring() {
    if (this.isMonitoring) {
      logger.warn('Behavioral monitoring is already running');
      return;
    }

    try {
      logger.info('Starting real-time behavioral monitoring');

      // Start consuming log events
      await this.startLogConsumption();

      // Schedule periodic analysis
      this.schedulePeriodicAnalysis();

      // Start real-time risk scoring
      this.startRealTimeRiskScoring();

      // Monitor system health
      this.startHealthMonitoring();

      this.isMonitoring = true;
      this.emit('monitoring:started');

      logger.info('Real-time behavioral monitoring started successfully');
    } catch (error) {
      logger.error('Error starting behavioral monitoring:', error);
      throw error;
    }
  }

  /**
   * Stop real-time behavioral monitoring
   */
  async stopMonitoring() {
    if (!this.isMonitoring) {
      logger.warn('Behavioral monitoring is not running');
      return;
    }

    try {
      logger.info('Stopping real-time behavioral monitoring');

      // Stop all monitoring intervals
      this.monitoringIntervals.forEach((interval, name) => {
        clearInterval(interval);
        logger.debug(`Stopped monitoring interval: ${name}`);
      });
      this.monitoringIntervals.clear();

      // Cancel all analysis tasks
      this.analysisTasks.forEach((task, id) => {
        if (task.timeout) {
          clearTimeout(task.timeout);
        }
        logger.debug(`Cancelled analysis task: ${id}`);
      });
      this.analysisTasks.clear();

      this.isMonitoring = false;
      this.emit('monitoring:stopped');

      logger.info('Real-time behavioral monitoring stopped');
    } catch (error) {
      logger.error('Error stopping behavioral monitoring:', error);
      throw error;
    }
  }

  /**
   * Start consuming log events for real-time analysis
   */
  async startLogConsumption() {
    try {
      // Listen for log events from RabbitMQ
      rabbitmqConsumer.on('log:received', this.handleLogEvent.bind(this));
      rabbitmqConsumer.on('security:event', this.handleSecurityEvent.bind(this));

      logger.info('Started consuming log events for behavioral analysis');
    } catch (error) {
      logger.error('Error starting log consumption:', error);
      throw error;
    }
  }

  /**
   * Handle incoming log events for real-time analysis
   */
  async handleLogEvent(logData) {
    try {
      const { level, source, event_type, ip_address, user_id, metadata } = logData;

      // Quick filtering for relevant events
      if (!this.isRelevantEvent(logData)) {
        return;
      }

      // User behavior analysis trigger
      if (user_id && this.isUserBehaviorEvent(logData)) {
        await this.triggerUserAnalysis(user_id, logData);
      }

      // Network behavior analysis trigger
      if (ip_address && this.isNetworkBehaviorEvent(logData)) {
        await this.triggerNetworkAnalysis(ip_address, 'ip', logData);
      }

      // Real-time alerting
      await this.checkRealTimeAlerts(logData);

    } catch (error) {
      logger.error('Error handling log event:', error);
    }
  }

  /**
   * Handle security events that require immediate attention
   */
  async handleSecurityEvent(eventData) {
    try {
      logger.warn('Security event received:', eventData);

      const { severity, event_type, entities } = eventData;

      // Immediate risk assessment for high-severity events
      if (severity === 'high' || severity === 'critical') {
        if (entities?.users) {
          for (const user of entities.users) {
            await this.performImmediateRiskAssessment('user', user.userId);
          }
        }

        if (entities?.networks) {
          for (const network of entities.networks) {
            await this.performImmediateRiskAssessment('network', network.ipAddress || network.subnet);
          }
        }

        // Trigger enhanced monitoring
        this.triggerEnhancedMonitoring(entities);
      }

      this.emit('security:event:processed', eventData);
    } catch (error) {
      logger.error('Error handling security event:', error);
    }
  }

  /**
   * Trigger user behavior analysis
   */
  async triggerUserAnalysis(userId, triggerEvent) {
    try {
      const analysisId = `user_${userId}_${Date.now()}`;
      
      // Check if analysis is already in progress
      if (this.analysisTasks.has(`user_${userId}`)) {
        logger.debug(`User analysis already in progress for: ${userId}`);
        return;
      }

      // Schedule analysis with debouncing
      const timeout = setTimeout(async () => {
        try {
          logger.debug(`Starting user behavior analysis for: ${userId}`);

          const analysis = await this.userAnalyzer.analyzeUserBehavior(userId);
          
          // Check for immediate alerts
          if (analysis.behaviorProfile) {
            await this.checkUserAlerts(analysis.behaviorProfile, analysis.mlAnalysis);
          }

          // Update risk score
          const riskAssessment = await riskScoringService.calculateUserRiskScore(userId, {
            triggerEvent,
            analysisResult: analysis,
          });

          this.emit('user:analysis:completed', {
            userId,
            analysis,
            riskAssessment,
            triggerEvent,
          });

          this.analysisTasks.delete(`user_${userId}`);
          logger.debug(`User behavior analysis completed for: ${userId}`);

        } catch (error) {
          logger.error(`Error in user analysis for ${userId}:`, error);
          this.analysisTasks.delete(`user_${userId}`);
        }
      }, 5000); // 5 second debounce

      this.analysisTasks.set(`user_${userId}`, {
        id: analysisId,
        type: 'user',
        identifier: userId,
        timeout,
        startTime: Date.now(),
      });

    } catch (error) {
      logger.error('Error triggering user analysis:', error);
    }
  }

  /**
   * Trigger network behavior analysis
   */
  async triggerNetworkAnalysis(identifier, identifierType, triggerEvent) {
    try {
      const analysisKey = `network_${identifierType}_${identifier}`;
      
      // Check if analysis is already in progress
      if (this.analysisTasks.has(analysisKey)) {
        logger.debug(`Network analysis already in progress for: ${identifier}`);
        return;
      }

      // Schedule analysis with debouncing
      const timeout = setTimeout(async () => {
        try {
          logger.debug(`Starting network behavior analysis for: ${identifier}`);

          const analysis = await this.networkAnalyzer.analyzeNetworkBehavior(identifier, identifierType);
          
          // Check for immediate alerts
          if (analysis.behaviorProfile) {
            await this.checkNetworkAlerts(analysis.behaviorProfile, analysis.mlAnalysis);
          }

          // Update risk score
          const riskAssessment = await riskScoringService.calculateNetworkRiskScore(identifier, identifierType, {
            triggerEvent,
            analysisResult: analysis,
          });

          this.emit('network:analysis:completed', {
            identifier,
            identifierType,
            analysis,
            riskAssessment,
            triggerEvent,
          });

          this.analysisTasks.delete(analysisKey);
          logger.debug(`Network behavior analysis completed for: ${identifier}`);

        } catch (error) {
          logger.error(`Error in network analysis for ${identifier}:`, error);
          this.analysisTasks.delete(analysisKey);
        }
      }, 10000); // 10 second debounce for network events

      this.analysisTasks.set(analysisKey, {
        id: `${analysisKey}_${Date.now()}`,
        type: 'network',
        identifier,
        identifierType,
        timeout,
        startTime: Date.now(),
      });

    } catch (error) {
      logger.error('Error triggering network analysis:', error);
    }
  }

  /**
   * Schedule periodic analysis for all entities
   */
  schedulePeriodicAnalysis() {
    // Hourly comprehensive user analysis
    const hourlyUserAnalysis = cron.schedule('0 * * * *', async () => {
      try {
        await this.performPeriodicUserAnalysis();
      } catch (error) {
        logger.error('Error in periodic user analysis:', error);
      }
    }, { scheduled: false });

    // Daily comprehensive network analysis
    const dailyNetworkAnalysis = cron.schedule('0 2 * * *', async () => {
      try {
        await this.performPeriodicNetworkAnalysis();
      } catch (error) {
        logger.error('Error in periodic network analysis:', error);
      }
    }, { scheduled: false });

    // Start scheduled tasks
    hourlyUserAnalysis.start();
    dailyNetworkAnalysis.start();

    this.monitoringIntervals.set('hourly_user_analysis', hourlyUserAnalysis);
    this.monitoringIntervals.set('daily_network_analysis', dailyNetworkAnalysis);

    logger.info('Scheduled periodic behavioral analysis tasks');
  }

  /**
   * Start real-time risk scoring
   */
  startRealTimeRiskScoring() {
    const riskScoringInterval = setInterval(async () => {
      try {
        await this.updateHighRiskEntities();
      } catch (error) {
        logger.error('Error in real-time risk scoring:', error);
      }
    }, 60000); // Every minute

    this.monitoringIntervals.set('risk_scoring', riskScoringInterval);
    logger.info('Started real-time risk scoring');
  }

  /**
   * Start health monitoring
   */
  startHealthMonitoring() {
    const healthInterval = setInterval(() => {
      try {
        this.performHealthCheck();
      } catch (error) {
        logger.error('Error in health monitoring:', error);
      }
    }, 30000); // Every 30 seconds

    this.monitoringIntervals.set('health_monitoring', healthInterval);
    logger.info('Started health monitoring');
  }

  /**
   * Check if event is relevant for behavioral analysis
   */
  isRelevantEvent(logData) {
    const relevantSources = ['auth', 'application', 'network', 'firewall', 'proxy'];
    const relevantEvents = ['login', 'logout', 'access', 'connection', 'transaction', 'error', 'security_violation'];
    
    return relevantSources.includes(logData.source) || 
           relevantEvents.some(event => logData.event_type?.includes(event));
  }

  /**
   * Check if event is relevant for user behavior analysis
   */
  isUserBehaviorEvent(logData) {
    const userEvents = ['login', 'logout', 'access', 'authentication', 'authorization'];
    return userEvents.some(event => 
      logData.event_type?.includes(event) || 
      logData.message?.toLowerCase().includes(event)
    );
  }

  /**
   * Check if event is relevant for network behavior analysis
   */
  isNetworkBehaviorEvent(logData) {
    const networkEvents = ['connection', 'traffic', 'network', 'firewall', 'proxy'];
    return networkEvents.some(event => 
      logData.event_type?.includes(event) || 
      logData.source?.includes(event)
    );
  }

  /**
   * Check for real-time alerts based on incoming data
   */
  async checkRealTimeAlerts(logData) {
    try {
      const alerts = [];

      // Check for immediate security concerns
      if (logData.level === 'critical' || logData.level === 'error') {
        alerts.push({
          type: 'immediate',
          severity: 'high',
          message: `Critical event detected: ${logData.message}`,
          source: logData,
        });
      }

      // Check for suspicious patterns
      if (this.isSuspiciousPattern(logData)) {
        alerts.push({
          type: 'pattern',
          severity: 'medium',
          message: 'Suspicious pattern detected',
          source: logData,
        });
      }

      // Emit alerts
      alerts.forEach(alert => {
        this.emit('realtime:alert', alert);
        logger.warn('Real-time alert generated:', alert);
      });

    } catch (error) {
      logger.error('Error checking real-time alerts:', error);
    }
  }

  /**
   * Check for user-specific alerts
   */
  async checkUserAlerts(behaviorProfile, mlAnalysis) {
    try {
      const alerts = [];
      const thresholds = this.alertThresholds.user;

      // Risk score threshold
      if (behaviorProfile.riskScores.overall >= thresholds.riskScore) {
        alerts.push({
          type: 'user_risk',
          severity: 'high',
          userId: behaviorProfile.userId,
          message: `User risk score exceeded threshold: ${behaviorProfile.riskScores.overall}`,
        });
      }

      // Anomaly count threshold
      const highSeverityAnomalies = behaviorProfile.anomalies.filter(a => 
        a.severity === 'high' || a.severity === 'critical'
      );
      
      if (highSeverityAnomalies.length >= thresholds.highSeverityAnomalies) {
        alerts.push({
          type: 'user_anomaly',
          severity: 'high',
          userId: behaviorProfile.userId,
          message: `Multiple high-severity anomalies detected: ${highSeverityAnomalies.length}`,
        });
      }

      // ML-based alerts
      if (mlAnalysis?.riskScore?.overall >= 80) {
        alerts.push({
          type: 'ml_risk',
          severity: 'high',
          userId: behaviorProfile.userId,
          message: `ML risk assessment indicates high risk: ${mlAnalysis.riskScore.overall}`,
        });
      }

      // Emit alerts
      alerts.forEach(alert => {
        this.emit('user:alert', alert);
        logger.warn('User alert generated:', alert);
      });

    } catch (error) {
      logger.error('Error checking user alerts:', error);
    }
  }

  /**
   * Check for network-specific alerts
   */
  async checkNetworkAlerts(behaviorProfile, mlAnalysis) {
    try {
      const alerts = [];
      const thresholds = this.alertThresholds.network;

      // Risk score threshold
      if (behaviorProfile.riskScores.overall >= thresholds.riskScore) {
        alerts.push({
          type: 'network_risk',
          severity: 'high',
          identifier: behaviorProfile.identifier,
          message: `Network risk score exceeded threshold: ${behaviorProfile.riskScores.overall}`,
        });
      }

      // Traffic spike detection
      const baseline = await this.getNetworkBaseline(behaviorProfile.identifier);
      if (baseline && behaviorProfile.trafficPatterns.averageBytesPerSecond > 
          baseline.averageBytesPerSecond * thresholds.trafficSpike) {
        alerts.push({
          type: 'traffic_spike',
          severity: 'medium',
          identifier: behaviorProfile.identifier,
          message: `Traffic spike detected: ${Math.round(behaviorProfile.trafficPatterns.averageBytesPerSecond / baseline.averageBytesPerSecond)}x normal`,
        });
      }

      // ML threat detection
      if (mlAnalysis?.threatDetection?.level === 'high' || mlAnalysis?.threatDetection?.level === 'critical') {
        alerts.push({
          type: 'ml_threat',
          severity: 'high',
          identifier: behaviorProfile.identifier,
          message: `ML threat detection indicates ${mlAnalysis.threatDetection.level} threat level`,
        });
      }

      // Emit alerts
      alerts.forEach(alert => {
        this.emit('network:alert', alert);
        logger.warn('Network alert generated:', alert);
      });

    } catch (error) {
      logger.error('Error checking network alerts:', error);
    }
  }

  /**
   * Perform immediate risk assessment
   */
  async performImmediateRiskAssessment(entityType, identifier) {
    try {
      logger.info(`Performing immediate risk assessment for ${entityType}: ${identifier}`);

      let riskAssessment;
      if (entityType === 'user') {
        riskAssessment = await riskScoringService.calculateUserRiskScore(identifier, {
          immediate: true,
        });
      } else if (entityType === 'network') {
        riskAssessment = await riskScoringService.calculateNetworkRiskScore(identifier, 'ip', {
          immediate: true,
        });
      }

      if (riskAssessment && (riskAssessment.level === 'critical' || riskAssessment.level === 'high')) {
        this.emit('immediate:risk:assessment', {
          entityType,
          identifier,
          riskAssessment,
        });

        logger.warn(`High risk detected in immediate assessment:`, {
          entityType,
          identifier,
          riskLevel: riskAssessment.level,
          riskScore: riskAssessment.overall,
        });
      }

    } catch (error) {
      logger.error('Error in immediate risk assessment:', error);
    }
  }

  /**
   * Helper methods
   */
  isSuspiciousPattern(logData) {
    const suspiciousKeywords = ['failed', 'denied', 'blocked', 'suspicious', 'malware', 'attack'];
    return suspiciousKeywords.some(keyword => 
      logData.message?.toLowerCase().includes(keyword)
    );
  }

  async performPeriodicUserAnalysis() {
    // Implementation for periodic user analysis
    logger.info('Performing periodic user analysis');
  }

  async performPeriodicNetworkAnalysis() {
    // Implementation for periodic network analysis
    logger.info('Performing periodic network analysis');
  }

  async updateHighRiskEntities() {
    // Implementation for updating high-risk entities
    logger.debug('Updating high-risk entities');
  }

  performHealthCheck() {
    const activeAnalysisTasks = this.analysisTasks.size;
    const maxConcurrent = this.alertThresholds.system.maxConcurrentAnalysis;

    if (activeAnalysisTasks > maxConcurrent) {
      logger.warn(`High number of concurrent analysis tasks: ${activeAnalysisTasks}`);
      this.emit('health:warning', {
        type: 'high_concurrency',
        activeAnalysisTasks,
        maxConcurrent,
      });
    }

    this.emit('health:check', {
      isMonitoring: this.isMonitoring,
      activeAnalysisTasks,
      cacheSize: this.behaviorCache.size,
    });
  }

  async getNetworkBaseline(identifier) {
    // Implementation to get network baseline
    return null;
  }

  triggerEnhancedMonitoring(entities) {
    // Implementation for enhanced monitoring
    logger.info('Triggering enhanced monitoring for entities:', entities);
  }
}

module.exports = new RealTimeBehaviorMonitor();