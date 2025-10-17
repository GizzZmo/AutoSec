/**
 * Advanced Threat Hunting Service
 * Provides comprehensive threat hunting capabilities including query execution,
 * hypothesis testing, IOC searching, and proactive threat detection
 */

const logger = require('../config/logger');
const ThreatHunt = require('../models/ThreatHunt');
const ThreatEvent = require('../models/ThreatEvent');
const IOC = require('../models/IOC');
const NetworkBehavior = require('../models/NetworkBehavior');
const { threatIntelService } = require('./threatIntelService');

class ThreatHuntingService {
  constructor() {
    this.activeHunts = new Map();
    this.huntTemplates = new Map();
    this.customQueries = new Map();
    
    this.initializeHuntTemplates();
  }

  /**
   * Initialize pre-built threat hunting templates
   */
  initializeHuntTemplates() {
    // APT Detection Template
    this.huntTemplates.set('apt-detection', {
      name: 'APT Activity Detection',
      description: 'Hunt for Advanced Persistent Threat indicators',
      queries: [
        {
          name: 'Unusual lateral movement',
          type: 'network',
          pattern: 'connection_count > 10 AND unique_destinations > 5',
          timeWindow: '1h'
        },
        {
          name: 'Suspicious process execution',
          type: 'behavior',
          pattern: 'rare_process AND elevated_privileges',
          timeWindow: '24h'
        },
        {
          name: 'Command and control beaconing',
          type: 'network',
          pattern: 'regular_intervals AND external_destination',
          timeWindow: '6h'
        }
      ],
      priority: 'high'
    });

    // Data Exfiltration Template
    this.huntTemplates.set('data-exfiltration', {
      name: 'Data Exfiltration Detection',
      description: 'Hunt for potential data exfiltration activities',
      queries: [
        {
          name: 'Large data transfers',
          type: 'network',
          pattern: 'bytes_out > 100MB AND destination NOT internal',
          timeWindow: '1h'
        },
        {
          name: 'Unusual upload activity',
          type: 'network',
          pattern: 'protocol IN (FTP, SFTP, HTTP POST) AND volume_anomaly',
          timeWindow: '24h'
        },
        {
          name: 'DNS tunneling',
          type: 'network',
          pattern: 'dns_query_length > 50 AND query_frequency > 100',
          timeWindow: '6h'
        }
      ],
      priority: 'high'
    });

    // Insider Threat Template
    this.huntTemplates.set('insider-threat', {
      name: 'Insider Threat Detection',
      description: 'Hunt for malicious insider activities',
      queries: [
        {
          name: 'After-hours access',
          type: 'behavior',
          pattern: 'login_time NOT IN working_hours AND access_sensitive',
          timeWindow: '24h'
        },
        {
          name: 'Privilege escalation attempts',
          type: 'behavior',
          pattern: 'failed_privilege_escalation OR unauthorized_access_attempt',
          timeWindow: '12h'
        },
        {
          name: 'Mass data access',
          type: 'behavior',
          pattern: 'file_access_count > 100 AND access_pattern_anomaly',
          timeWindow: '6h'
        }
      ],
      priority: 'medium'
    });

    // Ransomware Detection Template
    this.huntTemplates.set('ransomware', {
      name: 'Ransomware Activity Detection',
      description: 'Hunt for ransomware indicators',
      queries: [
        {
          name: 'Mass file encryption',
          type: 'behavior',
          pattern: 'file_modification_rate > 50 AND file_extension_changes',
          timeWindow: '30m'
        },
        {
          name: 'Shadow copy deletion',
          type: 'behavior',
          pattern: 'vssadmin OR bcdedit OR wbadmin',
          timeWindow: '1h'
        },
        {
          name: 'Ransomware communication',
          type: 'network',
          pattern: 'tor_exit_node OR known_ransomware_c2',
          timeWindow: '24h'
        }
      ],
      priority: 'critical'
    });

    logger.info('Initialized threat hunting templates');
  }

  /**
   * Start a new threat hunting campaign
   */
  async startThreatHunt(huntConfig) {
    try {
      const {
        name,
        description,
        hypothesis,
        queries = [],
        template,
        timeRange = '24h',
        targets = [],
        priority = 'medium',
        userId,
        automated = false
      } = huntConfig;

      // Use template if specified
      let finalQueries = queries;
      if (template && this.huntTemplates.has(template)) {
        const huntTemplate = this.huntTemplates.get(template);
        finalQueries = [...huntTemplate.queries, ...queries];
      }

      const hunt = new ThreatHunt({
        name,
        description,
        hypothesis,
        queries: finalQueries,
        template,
        timeRange,
        targets,
        priority,
        status: 'running',
        startTime: new Date(),
        userId,
        automated,
        findings: [],
        progress: {
          queriesExecuted: 0,
          totalQueries: finalQueries.length,
          percentage: 0
        }
      });

      await hunt.save();
      
      // Start hunt execution
      this.executeHunt(hunt);
      
      logger.info(`Started threat hunt: ${hunt._id} - ${name}`);
      
      return hunt;
    } catch (error) {
      logger.error('Error starting threat hunt:', error);
      throw error;
    }
  }

  /**
   * Execute threat hunting queries
   */
  async executeHunt(hunt) {
    try {
      logger.info(`Executing hunt: ${hunt._id}`);
      
      const findings = [];
      const startTime = Date.now();

      for (let i = 0; i < hunt.queries.length; i++) {
        const query = hunt.queries[i];
        
        try {
          logger.debug(`Executing query: ${query.name}`);
          
          // Execute query based on type
          let queryResults;
          switch (query.type) {
            case 'network':
              queryResults = await this.executeNetworkQuery(query, hunt);
              break;
            case 'behavior':
              queryResults = await this.executeBehaviorQuery(query, hunt);
              break;
            case 'ioc':
              queryResults = await this.executeIOCQuery(query, hunt);
              break;
            case 'threat_event':
              queryResults = await this.executeThreatEventQuery(query, hunt);
              break;
            default:
              queryResults = await this.executeCustomQuery(query, hunt);
          }

          if (queryResults && queryResults.length > 0) {
            findings.push({
              query: query.name,
              type: query.type,
              count: queryResults.length,
              results: queryResults,
              severity: this.calculateFindingSeverity(queryResults),
              timestamp: new Date()
            });
          }

          // Update progress
          hunt.progress.queriesExecuted = i + 1;
          hunt.progress.percentage = Math.round(((i + 1) / hunt.queries.length) * 100);
          await hunt.save();

        } catch (queryError) {
          logger.error(`Error executing query ${query.name}:`, queryError);
          findings.push({
            query: query.name,
            type: query.type,
            error: queryError.message,
            timestamp: new Date()
          });
        }
      }

      // Finalize hunt
      hunt.status = 'completed';
      hunt.endTime = new Date();
      hunt.findings = findings;
      hunt.summary = {
        totalFindings: findings.length,
        highSeverity: findings.filter(f => f.severity === 'high').length,
        mediumSeverity: findings.filter(f => f.severity === 'medium').length,
        lowSeverity: findings.filter(f => f.severity === 'low').length,
        executionTime: Date.now() - startTime
      };

      await hunt.save();

      // Generate threat events for significant findings
      await this.generateThreatEventsFromFindings(hunt, findings);

      logger.info(`Completed hunt: ${hunt._id} with ${findings.length} findings`);
      
      return hunt;
    } catch (error) {
      logger.error('Error executing hunt:', error);
      hunt.status = 'failed';
      hunt.error = error.message;
      await hunt.save();
      throw error;
    }
  }

  /**
   * Execute network-based threat hunting query
   */
  async executeNetworkQuery(query, hunt) {
    try {
      const timeRange = this.parseTimeRange(hunt.timeRange);
      const startTime = new Date(Date.now() - timeRange);

      // Build query based on pattern
      const queryFilter = this.buildNetworkQueryFilter(query.pattern, startTime);

      // Execute against NetworkBehavior collection
      const results = await NetworkBehavior.find(queryFilter)
        .sort({ timestamp: -1 })
        .limit(100)
        .lean();

      return results.map(result => ({
        type: 'network',
        timestamp: result.timestamp,
        sourceIP: result.sourceIP,
        destinationIP: result.destinationIP,
        protocol: result.protocol,
        bytes: result.bytes,
        anomalyScore: result.anomalyScore,
        details: result
      }));
    } catch (error) {
      logger.error('Error executing network query:', error);
      throw error;
    }
  }

  /**
   * Execute behavior-based threat hunting query
   */
  async executeBehaviorQuery(query, hunt) {
    try {
      const timeRange = this.parseTimeRange(hunt.timeRange);
      const startTime = new Date(Date.now() - timeRange);

      // Build query based on pattern
      const queryFilter = this.buildBehaviorQueryFilter(query.pattern, startTime);

      // Execute against ThreatEvent collection with behavior type
      const results = await ThreatEvent.find({
        ...queryFilter,
        timestamp: { $gte: startTime }
      })
        .sort({ timestamp: -1 })
        .limit(100)
        .lean();

      return results.map(result => ({
        type: 'behavior',
        timestamp: result.timestamp,
        eventType: result.eventType,
        severity: result.severity,
        title: result.title,
        description: result.description,
        riskScore: result.riskScore,
        details: result
      }));
    } catch (error) {
      logger.error('Error executing behavior query:', error);
      throw error;
    }
  }

  /**
   * Execute IOC-based threat hunting query
   */
  async executeIOCQuery(query, hunt) {
    try {
      const timeRange = this.parseTimeRange(hunt.timeRange);
      const startTime = new Date(Date.now() - timeRange);

      // Search for IOCs matching the pattern
      const queryFilter = this.buildIOCQueryFilter(query.pattern, startTime);

      const results = await IOC.find(queryFilter)
        .sort({ lastSeen: -1 })
        .limit(100)
        .lean();

      // Check for matches in recent events
      const enrichedResults = [];
      for (const ioc of results) {
        const matches = await this.findIOCMatches(ioc, startTime);
        if (matches.length > 0) {
          enrichedResults.push({
            type: 'ioc',
            iocType: ioc.type,
            iocValue: ioc.value,
            confidence: ioc.confidence,
            source: ioc.source,
            matches: matches.length,
            matchDetails: matches,
            details: ioc
          });
        }
      }

      return enrichedResults;
    } catch (error) {
      logger.error('Error executing IOC query:', error);
      throw error;
    }
  }

  /**
   * Execute threat event query
   */
  async executeThreatEventQuery(query, hunt) {
    try {
      const timeRange = this.parseTimeRange(hunt.timeRange);
      const startTime = new Date(Date.now() - timeRange);

      const queryFilter = this.buildThreatEventQueryFilter(query.pattern, startTime);

      const results = await ThreatEvent.find(queryFilter)
        .sort({ timestamp: -1 })
        .limit(100)
        .lean();

      return results.map(result => ({
        type: 'threat_event',
        eventId: result.eventId,
        eventType: result.eventType,
        severity: result.severity,
        title: result.title,
        riskScore: result.riskScore,
        timestamp: result.timestamp,
        details: result
      }));
    } catch (error) {
      logger.error('Error executing threat event query:', error);
      throw error;
    }
  }

  /**
   * Execute custom threat hunting query
   */
  async executeCustomQuery(query, hunt) {
    try {
      // For custom queries, we'll search across multiple data sources
      const timeRange = this.parseTimeRange(hunt.timeRange);
      const startTime = new Date(Date.now() - timeRange);

      const results = [];

      // Search in threat events
      const threatEvents = await ThreatEvent.find({
        timestamp: { $gte: startTime },
        $or: [
          { title: { $regex: query.pattern, $options: 'i' } },
          { description: { $regex: query.pattern, $options: 'i' } }
        ]
      }).limit(50).lean();

      results.push(...threatEvents.map(e => ({
        type: 'custom',
        source: 'threat_event',
        data: e
      })));

      // Search in IOCs
      const iocs = await IOC.find({
        lastSeen: { $gte: startTime },
        $or: [
          { value: { $regex: query.pattern, $options: 'i' } },
          { tags: { $regex: query.pattern, $options: 'i' } }
        ]
      }).limit(50).lean();

      results.push(...iocs.map(i => ({
        type: 'custom',
        source: 'ioc',
        data: i
      })));

      return results;
    } catch (error) {
      logger.error('Error executing custom query:', error);
      throw error;
    }
  }

  /**
   * Build network query filter from pattern
   */
  buildNetworkQueryFilter(pattern, startTime) {
    const filter = { timestamp: { $gte: startTime } };

    // Parse pattern and build filter
    // This is a simplified implementation - in production would be more sophisticated
    if (pattern.includes('connection_count >')) {
      const threshold = parseInt(pattern.match(/connection_count > (\d+)/)?.[1] || '10');
      filter.connectionCount = { $gt: threshold };
    }

    if (pattern.includes('external_destination')) {
      filter.$or = [
        { destinationIP: { $not: /^10\./ } },
        { destinationIP: { $not: /^172\.(1[6-9]|2[0-9]|3[01])\./ } },
        { destinationIP: { $not: /^192\.168\./ } }
      ];
    }

    if (pattern.includes('anomalyScore')) {
      filter.anomalyScore = { $gte: 0.7 };
    }

    return filter;
  }

  /**
   * Build behavior query filter from pattern
   */
  buildBehaviorQueryFilter(pattern, startTime) {
    const filter = { timestamp: { $gte: startTime } };

    if (pattern.includes('elevated_privileges')) {
      filter['entities.users.0.privilegeLevel'] = { $in: ['admin', 'root'] };
    }

    if (pattern.includes('rare_process')) {
      filter.eventType = { $in: ['unusual_process', 'suspicious_execution'] };
    }

    if (pattern.includes('failed_privilege_escalation')) {
      filter.eventType = 'privilege_escalation_attempt';
      filter.severity = { $in: ['high', 'critical'] };
    }

    return filter;
  }

  /**
   * Build IOC query filter from pattern
   */
  buildIOCQueryFilter(pattern, startTime) {
    const filter = { lastSeen: { $gte: startTime } };

    if (pattern.includes('type:')) {
      const type = pattern.match(/type:(\w+)/)?.[1];
      if (type) filter.type = type;
    }

    if (pattern.includes('confidence >')) {
      const threshold = parseFloat(pattern.match(/confidence > ([\d.]+)/)?.[1] || '0.7');
      filter.confidence = { $gte: threshold };
    }

    if (pattern.includes('source:')) {
      const source = pattern.match(/source:(\w+)/)?.[1];
      if (source) filter.source = source;
    }

    return filter;
  }

  /**
   * Build threat event query filter from pattern
   */
  buildThreatEventQueryFilter(pattern, startTime) {
    const filter = { timestamp: { $gte: startTime } };

    if (pattern.includes('severity:')) {
      const severity = pattern.match(/severity:(\w+)/)?.[1];
      if (severity) filter.severity = severity;
    }

    if (pattern.includes('riskScore >')) {
      const threshold = parseInt(pattern.match(/riskScore > (\d+)/)?.[1] || '70');
      filter.riskScore = { $gte: threshold };
    }

    if (pattern.includes('eventType:')) {
      const eventType = pattern.match(/eventType:([\w_]+)/)?.[1];
      if (eventType) filter.eventType = eventType;
    }

    return filter;
  }

  /**
   * Find matches for an IOC in recent data
   */
  async findIOCMatches(ioc, startTime) {
    const matches = [];

    try {
      if (ioc.type === 'ip' || ioc.type === 'ip-src' || ioc.type === 'ip-dst') {
        const networkMatches = await NetworkBehavior.find({
          timestamp: { $gte: startTime },
          $or: [
            { sourceIP: ioc.value },
            { destinationIP: ioc.value }
          ]
        }).limit(10).lean();

        matches.push(...networkMatches);
      } else if (ioc.type === 'domain' || ioc.type === 'hostname') {
        const threatMatches = await ThreatEvent.find({
          timestamp: { $gte: startTime },
          $or: [
            { 'entities.networks.domain': ioc.value },
            { description: { $regex: ioc.value, $options: 'i' } }
          ]
        }).limit(10).lean();

        matches.push(...threatMatches);
      }
    } catch (error) {
      logger.error('Error finding IOC matches:', error);
    }

    return matches;
  }

  /**
   * Calculate severity of findings
   */
  calculateFindingSeverity(results) {
    if (results.length === 0) return 'info';

    const avgScore = results.reduce((sum, r) => {
      return sum + (r.riskScore || r.anomalyScore || 50);
    }, 0) / results.length;

    if (avgScore >= 80) return 'high';
    if (avgScore >= 60) return 'medium';
    return 'low';
  }

  /**
   * Generate threat events from significant findings
   */
  async generateThreatEventsFromFindings(hunt, findings) {
    try {
      for (const finding of findings) {
        if (finding.severity === 'high' && finding.results && finding.results.length > 0) {
          const threatEvent = new ThreatEvent({
            eventId: `hunt-${hunt._id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            eventType: 'threat_hunting_finding',
            severity: finding.severity,
            title: `Threat Hunt Finding: ${finding.query}`,
            description: `Threat hunting campaign "${hunt.name}" discovered ${finding.count} potential threats`,
            source: {
              system: 'threat_hunting',
              detector: 'hunt_engine',
              huntId: hunt._id.toString(),
              huntName: hunt.name
            },
            evidence: {
              findings: finding.results.slice(0, 10), // Limit evidence
              query: finding.query
            },
            riskScore: finding.severity === 'high' ? 85 : finding.severity === 'medium' ? 65 : 45,
            timestamp: new Date(),
            status: 'open'
          });

          await threatEvent.save();
          logger.info(`Created threat event from hunt finding: ${threatEvent.eventId}`);
        }
      }
    } catch (error) {
      logger.error('Error generating threat events from findings:', error);
    }
  }

  /**
   * Get active threat hunts
   */
  async getActiveHunts(userId = null) {
    try {
      const filter = { status: { $in: ['running', 'pending'] } };
      if (userId) filter.userId = userId;

      const hunts = await ThreatHunt.find(filter)
        .sort({ startTime: -1 })
        .lean();

      return hunts;
    } catch (error) {
      logger.error('Error getting active hunts:', error);
      throw error;
    }
  }

  /**
   * Get threat hunt by ID
   */
  async getThreatHunt(huntId) {
    try {
      const hunt = await ThreatHunt.findById(huntId).lean();
      return hunt;
    } catch (error) {
      logger.error('Error getting threat hunt:', error);
      throw error;
    }
  }

  /**
   * Get all threat hunts with pagination
   */
  async getThreatHunts(filters = {}, page = 1, limit = 20) {
    try {
      const query = {};

      if (filters.status) query.status = filters.status;
      if (filters.priority) query.priority = filters.priority;
      if (filters.userId) query.userId = filters.userId;
      if (filters.template) query.template = filters.template;

      const skip = (page - 1) * limit;

      const [hunts, total] = await Promise.all([
        ThreatHunt.find(query)
          .sort({ startTime: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        ThreatHunt.countDocuments(query)
      ]);

      return {
        hunts,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting threat hunts:', error);
      throw error;
    }
  }

  /**
   * Stop a running threat hunt
   */
  async stopThreatHunt(huntId) {
    try {
      const hunt = await ThreatHunt.findById(huntId);
      
      if (!hunt) {
        throw new Error('Threat hunt not found');
      }

      if (hunt.status !== 'running') {
        throw new Error('Hunt is not running');
      }

      hunt.status = 'stopped';
      hunt.endTime = new Date();
      await hunt.save();

      logger.info(`Stopped threat hunt: ${huntId}`);
      return hunt;
    } catch (error) {
      logger.error('Error stopping threat hunt:', error);
      throw error;
    }
  }

  /**
   * Delete a threat hunt
   */
  async deleteThreatHunt(huntId) {
    try {
      const hunt = await ThreatHunt.findByIdAndDelete(huntId);
      
      if (!hunt) {
        throw new Error('Threat hunt not found');
      }

      logger.info(`Deleted threat hunt: ${huntId}`);
      return { success: true };
    } catch (error) {
      logger.error('Error deleting threat hunt:', error);
      throw error;
    }
  }

  /**
   * Get threat hunting statistics
   */
  async getThreatHuntingStats(userId = null) {
    try {
      const filter = userId ? { userId } : {};

      const [totalHunts, activeHunts, completedHunts, stats] = await Promise.all([
        ThreatHunt.countDocuments(filter),
        ThreatHunt.countDocuments({ ...filter, status: 'running' }),
        ThreatHunt.countDocuments({ ...filter, status: 'completed' }),
        ThreatHunt.aggregate([
          { $match: filter },
          {
            $group: {
              _id: '$priority',
              count: { $sum: 1 },
              avgFindings: { $avg: '$summary.totalFindings' }
            }
          }
        ])
      ]);

      return {
        totalHunts,
        activeHunts,
        completedHunts,
        byPriority: stats,
        availableTemplates: Array.from(this.huntTemplates.keys())
      };
    } catch (error) {
      logger.error('Error getting threat hunting stats:', error);
      throw error;
    }
  }

  /**
   * Parse time range string to milliseconds
   */
  parseTimeRange(timeRange) {
    const regex = /^(\d+)([mhd])$/;
    const match = timeRange.match(regex);

    if (!match) {
      return 24 * 60 * 60 * 1000; // Default 24 hours
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 'm':
        return value * 60 * 1000;
      case 'h':
        return value * 60 * 60 * 1000;
      case 'd':
        return value * 24 * 60 * 60 * 1000;
      default:
        return 24 * 60 * 60 * 1000;
    }
  }
}

// Create singleton instance
const threatHuntingService = new ThreatHuntingService();

module.exports = {
  threatHuntingService,
  ThreatHuntingService
};
