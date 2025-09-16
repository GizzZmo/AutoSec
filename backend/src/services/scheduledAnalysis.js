const cron = require('node-cron');
const UserBehaviorAnalyzer = require('./behaviorAnalysis');
const NetworkBehaviorAnalyzer = require('./networkBehaviorAnalysis');
const User = require('../models/User');
const Log = require('../models/Log');
const logger = require('../config/logger');

class ScheduledAnalysisService {
  constructor() {
    this.userBehaviorAnalyzer = new UserBehaviorAnalyzer();
    this.networkBehaviorAnalyzer = new NetworkBehaviorAnalyzer();
    this.isRunning = false;
    this.config = {
      userAnalysisSchedule: '0 2 * * *', // Daily at 2 AM
      networkAnalysisSchedule: '0 3 * * *', // Daily at 3 AM
      cleanupSchedule: '0 4 * * 0', // Weekly on Sunday at 4 AM
      batchSize: 10, // Process users in batches
      maxConcurrency: 3, // Maximum concurrent analyses
    };
  }

  /**
   * Start all scheduled tasks
   */
  start() {
    if (this.isRunning) {
      logger.warn('Scheduled analysis service is already running');
      return;
    }

    logger.info('Starting scheduled analysis service');
    this.isRunning = true;

    // Schedule user behavior analysis
    this.userAnalysisTask = cron.schedule(this.config.userAnalysisSchedule, async () => {
      await this.runUserBehaviorAnalysis();
    }, {
      scheduled: false,
      timezone: process.env.TZ || 'UTC',
    });

    // Schedule network behavior analysis
    this.networkAnalysisTask = cron.schedule(this.config.networkAnalysisSchedule, async () => {
      await this.runNetworkBehaviorAnalysis();
    }, {
      scheduled: false,
      timezone: process.env.TZ || 'UTC',
    });

    // Schedule cleanup tasks
    this.cleanupTask = cron.schedule(this.config.cleanupSchedule, async () => {
      await this.runCleanupTasks();
    }, {
      scheduled: false,
      timezone: process.env.TZ || 'UTC',
    });

    // Start all tasks
    this.userAnalysisTask.start();
    this.networkAnalysisTask.start();
    this.cleanupTask.start();

    logger.info('Scheduled analysis service started successfully');
  }

  /**
   * Stop all scheduled tasks
   */
  stop() {
    if (!this.isRunning) {
      logger.warn('Scheduled analysis service is not running');
      return;
    }

    logger.info('Stopping scheduled analysis service');

    if (this.userAnalysisTask) {
      this.userAnalysisTask.stop();
      this.userAnalysisTask = null;
    }

    if (this.networkAnalysisTask) {
      this.networkAnalysisTask.stop();
      this.networkAnalysisTask = null;
    }

    if (this.cleanupTask) {
      this.cleanupTask.stop();
      this.cleanupTask = null;
    }

    this.isRunning = false;
    logger.info('Scheduled analysis service stopped');
  }

  /**
   * Run user behavior analysis for all active users
   */
  async runUserBehaviorAnalysis() {
    const startTime = Date.now();
    logger.info('Starting scheduled user behavior analysis');

    try {
      // Get all active users
      const users = await User.findAll({
        where: { isActive: true },
        attributes: ['id', 'username'],
        order: [['lastLogin', 'DESC']], // Prioritize recently active users
      });

      logger.info(`Found ${users.length} active users for analysis`);

      let successCount = 0;
      let errorCount = 0;
      const errors = [];

      // Process users in batches
      for (let i = 0; i < users.length; i += this.config.batchSize) {
        const batch = users.slice(i, i + this.config.batchSize);
        
        const batchPromises = batch.map(async (user) => {
          try {
            const profile = await this.userBehaviorAnalyzer.analyzeUserBehavior(user.id);
            if (profile) {
              successCount++;
              logger.debug(`User behavior analysis completed for user ${user.username}`);
            }
          } catch (error) {
            errorCount++;
            errors.push({ userId: user.id, username: user.username, error: error.message });
            logger.error(`Error analyzing user ${user.username}:`, error);
          }
        });

        // Wait for current batch to complete before processing next batch
        await Promise.all(batchPromises);

        // Small delay between batches to prevent overwhelming the system
        if (i + this.config.batchSize < users.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }

      const duration = Date.now() - startTime;
      logger.info('Scheduled user behavior analysis completed', {
        totalUsers: users.length,
        successCount,
        errorCount,
        duration: `${duration}ms`,
      });

      // Log errors if any
      if (errors.length > 0) {
        logger.warn('User behavior analysis errors:', { errors: errors.slice(0, 10) }); // Log first 10 errors
      }

    } catch (error) {
      logger.error('Error in scheduled user behavior analysis:', error);
    }
  }

  /**
   * Run network behavior analysis for active IP addresses
   */
  async runNetworkBehaviorAnalysis() {
    const startTime = Date.now();
    logger.info('Starting scheduled network behavior analysis');

    try {
      // Get unique IP addresses from recent logs (last 24 hours)
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      const recentIPs = await Log.aggregate([
        {
          $match: {
            ip_address: { $exists: true, $ne: null },
            timestamp: { $gte: oneDayAgo },
          },
        },
        {
          $group: {
            _id: '$ip_address',
            logCount: { $sum: 1 },
            lastSeen: { $max: '$timestamp' },
          },
        },
        {
          $match: {
            logCount: { $gte: 5 }, // Only analyze IPs with at least 5 log entries
          },
        },
        {
          $sort: { logCount: -1 },
        },
        {
          $limit: 100, // Limit to top 100 most active IPs
        },
      ]);

      logger.info(`Found ${recentIPs.length} IP addresses for network analysis`);

      let successCount = 0;
      let errorCount = 0;
      const errors = [];

      // Process IPs in batches
      for (let i = 0; i < recentIPs.length; i += this.config.batchSize) {
        const batch = recentIPs.slice(i, i + this.config.batchSize);
        
        const batchPromises = batch.map(async (ipData) => {
          try {
            const profile = await this.networkBehaviorAnalyzer.analyzeNetworkBehavior(
              ipData._id, 
              'ip'
            );
            if (profile) {
              successCount++;
              logger.debug(`Network behavior analysis completed for IP ${ipData._id}`);
            }
          } catch (error) {
            errorCount++;
            errors.push({ ip: ipData._id, error: error.message });
            logger.error(`Error analyzing IP ${ipData._id}:`, error);
          }
        });

        // Wait for current batch to complete
        await Promise.all(batchPromises);

        // Small delay between batches
        if (i + this.config.batchSize < recentIPs.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }

      const duration = Date.now() - startTime;
      logger.info('Scheduled network behavior analysis completed', {
        totalIPs: recentIPs.length,
        successCount,
        errorCount,
        duration: `${duration}ms`,
      });

      // Log errors if any
      if (errors.length > 0) {
        logger.warn('Network behavior analysis errors:', { errors: errors.slice(0, 10) });
      }

    } catch (error) {
      logger.error('Error in scheduled network behavior analysis:', error);
    }
  }

  /**
   * Run cleanup tasks
   */
  async runCleanupTasks() {
    const startTime = Date.now();
    logger.info('Starting scheduled cleanup tasks');

    try {
      const tasks = [];

      // Cleanup old behavioral profiles (older than 90 days)
      tasks.push(this.cleanupOldBehavioralProfiles());

      // Cleanup resolved threat events (older than 30 days)
      tasks.push(this.cleanupResolvedThreatEvents());

      // Cleanup old logs (older than configured retention period)
      tasks.push(this.cleanupOldLogs());

      // Update anomaly statuses
      tasks.push(this.updateAnomalyStatuses());

      // Run all cleanup tasks concurrently
      const results = await Promise.allSettled(tasks);

      const duration = Date.now() - startTime;
      const successCount = results.filter(r => r.status === 'fulfilled').length;
      const errorCount = results.filter(r => r.status === 'rejected').length;

      logger.info('Scheduled cleanup tasks completed', {
        totalTasks: tasks.length,
        successCount,
        errorCount,
        duration: `${duration}ms`,
      });

      // Log any errors
      results.forEach((result, index) => {
        if (result.status === 'rejected') {
          logger.error(`Cleanup task ${index} failed:`, result.reason);
        }
      });

    } catch (error) {
      logger.error('Error in scheduled cleanup tasks:', error);
    }
  }

  /**
   * Cleanup old behavioral profiles
   */
  async cleanupOldBehavioralProfiles() {
    const UserBehavior = require('../models/UserBehavior');
    const NetworkBehavior = require('../models/NetworkBehavior');
    
    const cutoffDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days ago

    // Delete old user behavior profiles
    const deletedUserProfiles = await UserBehavior.deleteMany({
      'profilePeriod.endDate': { $lt: cutoffDate },
    });

    // Delete old network behavior profiles
    const deletedNetworkProfiles = await NetworkBehavior.deleteMany({
      'profilePeriod.endDate': { $lt: cutoffDate },
    });

    logger.info('Cleaned up old behavioral profiles', {
      deletedUserProfiles: deletedUserProfiles.deletedCount,
      deletedNetworkProfiles: deletedNetworkProfiles.deletedCount,
    });
  }

  /**
   * Cleanup resolved threat events
   */
  async cleanupResolvedThreatEvents() {
    const ThreatEvent = require('../models/ThreatEvent');
    
    const cutoffDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago

    const deletedEvents = await ThreatEvent.deleteMany({
      status: { $in: ['resolved', 'false_positive'] },
      'resolved.at': { $lt: cutoffDate },
    });

    logger.info('Cleaned up resolved threat events', {
      deletedEvents: deletedEvents.deletedCount,
    });
  }

  /**
   * Cleanup old logs based on retention policy
   */
  async cleanupOldLogs() {
    // Default retention: 180 days for regular logs, 365 days for critical logs
    const regularCutoff = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000);
    const criticalCutoff = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);

    // Delete old regular logs
    const deletedRegularLogs = await Log.deleteMany({
      timestamp: { $lt: regularCutoff },
      level: { $nin: ['critical', 'error'] },
    });

    // Delete old critical logs
    const deletedCriticalLogs = await Log.deleteMany({
      timestamp: { $lt: criticalCutoff },
      level: { $in: ['critical', 'error'] },
    });

    logger.info('Cleaned up old logs', {
      deletedRegularLogs: deletedRegularLogs.deletedCount,
      deletedCriticalLogs: deletedCriticalLogs.deletedCount,
    });
  }

  /**
   * Update anomaly statuses
   */
  async updateAnomalyStatuses() {
    const UserBehavior = require('../models/UserBehavior');
    const NetworkBehavior = require('../models/NetworkBehavior');
    
    // Mark old anomalies as resolved if no recent activity
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    // Update user behavior anomalies
    const updatedUserAnomalies = await UserBehavior.updateMany(
      {
        'anomalies.timestamp': { $lt: sevenDaysAgo },
        'anomalies.resolved': false,
        'anomalies.severity': { $in: ['low', 'medium'] },
      },
      {
        $set: { 'anomalies.$.resolved': true },
      }
    );

    // Update network behavior anomalies
    const updatedNetworkAnomalies = await NetworkBehavior.updateMany(
      {
        'anomalies.timestamp': { $lt: sevenDaysAgo },
        'anomalies.resolved': false,
        'anomalies.severity': { $in: ['low', 'medium'] },
      },
      {
        $set: { 'anomalies.$.resolved': true },
      }
    );

    logger.info('Updated anomaly statuses', {
      updatedUserAnomalies: updatedUserAnomalies.modifiedCount,
      updatedNetworkAnomalies: updatedNetworkAnomalies.modifiedCount,
    });
  }

  /**
   * Get service status
   */
  getStatus() {
    return {
      isRunning: this.isRunning,
      config: this.config,
      nextRuns: this.isRunning ? {
        userAnalysis: this.userAnalysisTask?.nextDates(),
        networkAnalysis: this.networkAnalysisTask?.nextDates(),
        cleanup: this.cleanupTask?.nextDates(),
      } : null,
    };
  }

  /**
   * Manually trigger user behavior analysis
   */
  async triggerUserAnalysis() {
    if (!this.isRunning) {
      throw new Error('Scheduled analysis service is not running');
    }
    
    logger.info('Manually triggering user behavior analysis');
    await this.runUserBehaviorAnalysis();
  }

  /**
   * Manually trigger network behavior analysis
   */
  async triggerNetworkAnalysis() {
    if (!this.isRunning) {
      throw new Error('Scheduled analysis service is not running');
    }
    
    logger.info('Manually triggering network behavior analysis');
    await this.runNetworkBehaviorAnalysis();
  }

  /**
   * Manually trigger cleanup tasks
   */
  async triggerCleanup() {
    if (!this.isRunning) {
      throw new Error('Scheduled analysis service is not running');
    }
    
    logger.info('Manually triggering cleanup tasks');
    await this.runCleanupTasks();
  }
}

module.exports = ScheduledAnalysisService;