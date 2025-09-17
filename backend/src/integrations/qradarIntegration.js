/**
 * QRadar SIEM Integration
 * Provides integration with IBM QRadar Security Intelligence Platform
 */

const axios = require('axios');
const https = require('https');
const logger = require('../config/logger');

class QRadarIntegration {
  constructor(config) {
    this.config = config;
    this.baseUrl = `${config.protocol}://${config.hostname}:${config.port}`;
    this.apiToken = config.apiToken;
    this.apiVersion = config.version;
    this.httpClient = this.createHttpClient();
  }

  /**
   * Create HTTP client with authentication
   */
  createHttpClient() {
    return axios.create({
      baseURL: this.baseUrl,
      timeout: 30000,
      headers: {
        'SEC': this.apiToken,
        'Version': this.apiVersion,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false // For self-signed certificates
      })
    });
  }

  /**
   * Initialize the integration
   */
  async initialize() {
    try {
      logger.info('Initializing QRadar integration...');
      
      // Test connectivity
      await this.healthCheck();
      
      logger.info('QRadar integration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize QRadar integration:', error);
      throw error;
    }
  }

  /**
   * Send security event to QRadar
   */
  async sendEvent(event, options = {}) {
    try {
      // QRadar uses syslog format for custom events
      const qradarEvent = this.formatEventForQRadar(event);
      
      const response = await this.httpClient.post('/api/siem/events', {
        events: [qradarEvent]
      });

      logger.debug('Event sent to QRadar successfully');
      return {
        success: true,
        eventId: qradarEvent.id,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to send event to QRadar:', error);
      throw error;
    }
  }

  /**
   * Send multiple events in batch to QRadar
   */
  async sendBatchEvents(events, options = {}) {
    try {
      const qradarEvents = events.map(event => this.formatEventForQRadar(event));

      const response = await this.httpClient.post('/api/siem/events', {
        events: qradarEvents
      });

      logger.debug(`Batch of ${events.length} events sent to QRadar successfully`);
      return {
        success: true,
        eventsCount: events.length,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to send batch events to QRadar:', error);
      throw error;
    }
  }

  /**
   * Query QRadar for events using AQL (Ariel Query Language)
   */
  async queryEvents(aqlQuery, options = {}) {
    try {
      // Start AQL search
      const searchResponse = await this.httpClient.post('/api/ariel/searches', {
        query_expression: aqlQuery
      });

      const searchId = searchResponse.data.search_id;
      logger.debug(`Started QRadar AQL search with ID: ${searchId}`);

      // Wait for search to complete
      await this.waitForSearchCompletion(searchId);

      // Get search results
      const resultsResponse = await this.httpClient.get(`/api/ariel/searches/${searchId}/results`, {
        params: {
          Range: `items=0-${options.limit || 999}`
        }
      });

      logger.debug(`QRadar query completed, found ${resultsResponse.data.events?.length || 0} results`);
      return {
        success: true,
        results: resultsResponse.data.events || [],
        searchId: searchId
      };
    } catch (error) {
      logger.error('Failed to query QRadar:', error);
      throw error;
    }
  }

  /**
   * Create offense (alert) in QRadar
   */
  async createAlert(alert, options = {}) {
    try {
      // Create a custom rule that will generate an offense
      const ruleConfig = {
        name: alert.name || alert.title,
        type: 'EVENT',
        origin: 'USER',
        enabled: true,
        owner: 'autosec',
        notes: alert.description,
        test_groups: [{
          name: 'AutoSec Alert Group',
          tests: [{
            test: `SELECT * FROM events WHERE sourceip='${alert.source_ip || '0.0.0.0'}' AND devicetype='AutoSec'`,
            uid: Date.now()
          }]
        }],
        responses: [{
          name: 'Create Offense',
          type: 'OFFENSE',
          severity: this.mapSeverity(alert.severity),
          credibility: alert.confidence ? Math.round(alert.confidence * 10) : 5,
          relevance: alert.risk_score ? Math.round(alert.risk_score / 10) : 5
        }]
      };

      const response = await this.httpClient.post('/api/analytics/rules', ruleConfig);

      logger.info(`Alert rule '${alert.name}' created in QRadar`);
      return {
        success: true,
        ruleId: response.data.id,
        ruleName: alert.name,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to create alert in QRadar:', error);
      throw error;
    }
  }

  /**
   * Get offenses (security incidents) from QRadar
   */
  async getOffenses(options = {}) {
    try {
      const params = {
        fields: 'id,description,offense_type,status,magnitude,credibility,relevance,assigned_to,start_time,last_updated_time,source_network,destination_networks,categories,source_count,event_count,flow_count',
        sort: options.sort || '-start_time',
        Range: `items=0-${options.limit || 99}`
      };

      if (options.filter) {
        params.filter = options.filter;
      }

      const response = await this.httpClient.get('/api/siem/offenses', { params });

      return {
        success: true,
        offenses: response.data || []
      };
    } catch (error) {
      logger.error('Failed to get offenses from QRadar:', error);
      throw error;
    }
  }

  /**
   * Get reference data sets from QRadar
   */
  async getReferenceSets() {
    try {
      const response = await this.httpClient.get('/api/reference_data/sets');

      return {
        success: true,
        referenceSets: response.data || []
      };
    } catch (error) {
      logger.error('Failed to get reference sets from QRadar:', error);
      throw error;
    }
  }

  /**
   * Add IP to reference set (e.g., blocked IPs list)
   */
  async addToReferenceSet(setName, value, source = 'AutoSec') {
    try {
      const response = await this.httpClient.post(`/api/reference_data/sets/${setName}`, {
        value: value,
        source: source
      });

      logger.info(`Added ${value} to QRadar reference set: ${setName}`);
      return {
        success: true,
        value: value,
        setName: setName,
        response: response.status
      };
    } catch (error) {
      logger.error(`Failed to add ${value} to QRadar reference set ${setName}:`, error);
      throw error;
    }
  }

  /**
   * Get log sources from QRadar
   */
  async getLogSources() {
    try {
      const response = await this.httpClient.get('/api/config/event_sources/log_source_management/log_sources', {
        params: {
          fields: 'id,name,description,type_id,protocol_type_id,enabled,status,average_eps'
        }
      });

      return {
        success: true,
        logSources: response.data || []
      };
    } catch (error) {
      logger.error('Failed to get log sources from QRadar:', error);
      throw error;
    }
  }

  /**
   * Get saved searches (reports) from QRadar
   */
  async getSavedSearches() {
    try {
      const response = await this.httpClient.get('/api/analytics/saved_search_groups');

      return {
        success: true,
        savedSearches: response.data || []
      };
    } catch (error) {
      logger.error('Failed to get saved searches from QRadar:', error);
      throw error;
    }
  }

  /**
   * Get dashboards from QRadar
   */
  async getDashboards() {
    try {
      const response = await this.httpClient.get('/api/gui_app_framework/applications');

      return {
        success: true,
        dashboards: response.data || []
      };
    } catch (error) {
      logger.error('Failed to get dashboards from QRadar:', error);
      throw error;
    }
  }

  /**
   * Format event for QRadar consumption
   */
  formatEventForQRadar(event) {
    return {
      id: event.id || event.eventId || Date.now().toString(),
      timestamp: event.timestamp ? new Date(event.timestamp).getTime() : Date.now(),
      magnitude: this.calculateMagnitude(event.severity, event.risk_score),
      eventname: event.type || event.eventType || 'AutoSec Event',
      sourceip: event.source_ip || event.sourceIp || '0.0.0.0',
      destinationip: event.destination_ip || event.destinationIp,
      username: event.user || event.username,
      protocolid: 0, // TCP
      devicetype: 2000, // Custom device type for AutoSec
      logsourceid: 1,
      category: this.mapCategory(event.type),
      description: event.description || event.title,
      severity: this.mapSeverity(event.severity),
      credibility: event.confidence ? Math.round(event.confidence * 10) : 5,
      relevance: event.risk_score ? Math.round(event.risk_score / 10) : 5,
      properties: {
        autosec_event_id: event.id || event.eventId,
        autosec_source: 'AutoSec Platform',
        autosec_evidence: JSON.stringify(event.evidence || {}),
        autosec_entities: JSON.stringify(event.entities || {})
      }
    };
  }

  /**
   * Calculate QRadar magnitude based on severity and risk score
   */
  calculateMagnitude(severity, riskScore) {
    const severityWeights = {
      'critical': 8,
      'high': 6,
      'medium': 4,
      'low': 2,
      'info': 1
    };

    const severityWeight = severityWeights[severity?.toLowerCase()] || 4;
    const riskWeight = riskScore ? Math.round(riskScore / 10) : 5;
    
    return Math.min(10, Math.max(1, Math.round((severityWeight + riskWeight) / 2)));
  }

  /**
   * Map AutoSec severity to QRadar severity
   */
  mapSeverity(severity) {
    const severityMap = {
      'critical': 10,
      'high': 8,
      'medium': 5,
      'low': 3,
      'info': 1
    };
    return severityMap[severity?.toLowerCase()] || 5;
  }

  /**
   * Map event type to QRadar category
   */
  mapCategory(eventType) {
    const categoryMap = {
      'threat_intelligence_match': 1002, // Suspicious Activity
      'behavioral_deviation': 1003, // Policy Violation
      'anomaly_detection': 1004, // System Anomaly
      'rule_violation': 1005, // Access Violation
      'default': 1000 // Unknown
    };
    return categoryMap[eventType] || categoryMap.default;
  }

  /**
   * Wait for AQL search completion
   */
  async waitForSearchCompletion(searchId, maxWaitTime = 30000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      try {
        const response = await this.httpClient.get(`/api/ariel/searches/${searchId}`);
        
        const status = response.data.status;
        if (status === 'COMPLETED') {
          return true;
        } else if (status === 'ERROR' || status === 'CANCELED') {
          throw new Error(`Search failed with status: ${status}`);
        }

        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (error) {
        logger.error('Error checking search status:', error);
        throw error;
      }
    }

    throw new Error('Search timed out');
  }

  /**
   * Perform health check
   */
  async healthCheck() {
    try {
      const response = await this.httpClient.get('/api/system/about');
      return response.status === 200;
    } catch (error) {
      logger.error('QRadar health check failed:', error);
      return false;
    }
  }

  /**
   * Get integration info
   */
  getInfo() {
    return {
      type: 'qradar',
      baseUrl: this.baseUrl,
      apiVersion: this.apiVersion,
      status: 'connected'
    };
  }
}

module.exports = QRadarIntegration;