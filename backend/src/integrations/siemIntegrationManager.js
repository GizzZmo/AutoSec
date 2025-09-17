/**
 * SIEM Integration Manager
 * Manages integrations with Security Information and Event Management systems
 */

const SplunkIntegration = require('./splunkIntegration');
const QRadarIntegration = require('./qradarIntegration');
const logger = require('../config/logger');

class SIEMIntegrationManager {
  constructor() {
    this.integrations = new Map();
    this.config = this.loadConfiguration();
    this.healthStatus = new Map();
    this.lastHealthCheck = null;
    this.eventBuffer = [];
    this.maxBufferSize = 1000;
  }

  /**
   * Load SIEM configurations from environment
   */
  loadConfiguration() {
    return {
      splunk: {
        enabled: process.env.SPLUNK_ENABLED === 'true',
        hostname: process.env.SPLUNK_HOST,
        port: process.env.SPLUNK_PORT || 8089,
        username: process.env.SPLUNK_USERNAME,
        password: process.env.SPLUNK_PASSWORD,
        protocol: process.env.SPLUNK_PROTOCOL || 'https',
        index: process.env.SPLUNK_INDEX || 'autosec',
        sourcetype: process.env.SPLUNK_SOURCETYPE || 'autosec:events',
      },
      qradar: {
        enabled: process.env.QRADAR_ENABLED === 'true',
        hostname: process.env.QRADAR_HOST,
        port: process.env.QRADAR_PORT || 443,
        apiToken: process.env.QRADAR_API_TOKEN,
        protocol: process.env.QRADAR_PROTOCOL || 'https',
        version: process.env.QRADAR_API_VERSION || '16.0',
      },
    };
  }

  /**
   * Initialize all enabled SIEM integrations
   */
  async initialize() {
    try {
      logger.info('Initializing SIEM integrations...');

      // Initialize Splunk
      if (this.config.splunk.enabled) {
        await this.initializeIntegration('splunk', new SplunkIntegration(this.config.splunk));
      }

      // Initialize QRadar
      if (this.config.qradar.enabled) {
        await this.initializeIntegration('qradar', new QRadarIntegration(this.config.qradar));
      }

      logger.info(`SIEM integrations initialized: ${Array.from(this.integrations.keys()).join(', ')}`);
    } catch (error) {
      logger.error('Error initializing SIEM integrations:', error);
      throw error;
    }
  }

  /**
   * Initialize a specific integration
   */
  async initializeIntegration(name, integration) {
    try {
      await integration.initialize();
      this.integrations.set(name, integration);
      this.healthStatus.set(name, { status: 'healthy', lastCheck: Date.now() });
      logger.info(`SIEM integration '${name}' initialized successfully`);
    } catch (error) {
      logger.error(`Failed to initialize SIEM integration '${name}':`, error);
      this.healthStatus.set(name, { status: 'error', error: error.message, lastCheck: Date.now() });
      throw error;
    }
  }

  /**
   * Send security event to all SIEM systems
   */
  async sendEvent(event, options = {}) {
    const results = [];
    const errors = [];

    // Add event to buffer
    this.addToBuffer(event);

    // Normalize event for SIEM systems
    const normalizedEvent = this.normalizeEvent(event);

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Sending event to SIEM system: ${name}`);
        const result = await integration.sendEvent(normalizedEvent, options);
        results.push({ integration: name, success: true, result });
      } catch (error) {
        logger.error(`Failed to send event to ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Send multiple events in batch
   */
  async sendBatchEvents(events, options = {}) {
    const results = [];
    const errors = [];

    // Add events to buffer
    events.forEach(event => this.addToBuffer(event));

    // Normalize events
    const normalizedEvents = events.map(event => this.normalizeEvent(event));

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Sending ${events.length} events to SIEM system: ${name}`);
        const result = await integration.sendBatchEvents(normalizedEvents, options);
        results.push({ integration: name, success: true, result });
      } catch (error) {
        logger.error(`Failed to send batch events to ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Query SIEM systems for events
   */
  async queryEvents(query, options = {}) {
    const results = {};
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Querying SIEM system: ${name}`);
        const result = await integration.queryEvents(query, options);
        results[name] = result;
      } catch (error) {
        logger.error(`Failed to query ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors };
  }

  /**
   * Create alert in SIEM systems
   */
  async createAlert(alert, options = {}) {
    const results = [];
    const errors = [];

    // Normalize alert for SIEM systems
    const normalizedAlert = this.normalizeAlert(alert);

    for (const [name, integration] of this.integrations) {
      try {
        logger.info(`Creating alert in SIEM system: ${name}`);
        const result = await integration.createAlert(normalizedAlert, options);
        results.push({ integration: name, success: true, result });
      } catch (error) {
        logger.error(`Failed to create alert in ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Get dashboards from SIEM systems
   */
  async getDashboards() {
    const dashboards = {};
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Fetching dashboards from SIEM system: ${name}`);
        const result = await integration.getDashboards();
        dashboards[name] = result;
      } catch (error) {
        logger.error(`Failed to get dashboards from ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { dashboards, errors };
  }

  /**
   * Get saved searches from SIEM systems
   */
  async getSavedSearches() {
    const searches = {};
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Fetching saved searches from SIEM system: ${name}`);
        const result = await integration.getSavedSearches();
        searches[name] = result;
      } catch (error) {
        logger.error(`Failed to get saved searches from ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { searches, errors };
  }

  /**
   * Normalize event for SIEM consumption
   */
  normalizeEvent(event) {
    return {
      timestamp: event.timestamp || new Date().toISOString(),
      source: 'AutoSec',
      sourcetype: 'autosec:event',
      event: {
        id: event.id || event.eventId,
        type: event.type || event.eventType,
        severity: event.severity,
        title: event.title,
        description: event.description,
        source_ip: event.sourceIp || event.ipAddress,
        destination_ip: event.destinationIp,
        user: event.user || event.username,
        action: event.action,
        status: event.status,
        risk_score: event.riskScore,
        evidence: event.evidence,
        entities: event.entities,
        raw_event: event
      }
    };
  }

  /**
   * Normalize alert for SIEM consumption
   */
  normalizeAlert(alert) {
    return {
      timestamp: alert.timestamp || new Date().toISOString(),
      source: 'AutoSec',
      alert: {
        id: alert.id || alert.alertId,
        name: alert.name || alert.title,
        description: alert.description,
        severity: alert.severity,
        priority: alert.priority,
        category: alert.category || 'Security',
        subcategory: alert.subcategory || 'Threat Detection',
        source_ip: alert.sourceIp,
        destination_ip: alert.destinationIp,
        user: alert.user,
        status: alert.status || 'Open',
        confidence: alert.confidence,
        risk_score: alert.riskScore,
        mitigation_actions: alert.mitigationActions,
        evidence: alert.evidence,
        raw_alert: alert
      }
    };
  }

  /**
   * Add event to internal buffer
   */
  addToBuffer(event) {
    this.eventBuffer.push({
      ...event,
      buffered_at: Date.now()
    });

    // Maintain buffer size
    if (this.eventBuffer.length > this.maxBufferSize) {
      this.eventBuffer.shift();
    }
  }

  /**
   * Get buffered events
   */
  getBufferedEvents(limit = 100) {
    return this.eventBuffer.slice(-limit);
  }

  /**
   * Clear event buffer
   */
  clearBuffer() {
    this.eventBuffer = [];
  }

  /**
   * Perform health check on all integrations
   */
  async performHealthCheck() {
    logger.info('Performing SIEM integration health check...');
    this.lastHealthCheck = Date.now();

    for (const [name, integration] of this.integrations) {
      try {
        const isHealthy = await integration.healthCheck();
        this.healthStatus.set(name, {
          status: isHealthy ? 'healthy' : 'unhealthy',
          lastCheck: this.lastHealthCheck,
        });
      } catch (error) {
        logger.error(`Health check failed for SIEM integration '${name}':`, error);
        this.healthStatus.set(name, {
          status: 'error',
          error: error.message,
          lastCheck: this.lastHealthCheck,
        });
      }
    }

    return {
      timestamp: this.lastHealthCheck,
      integrations: Object.fromEntries(this.healthStatus),
    };
  }

  /**
   * Get integration capabilities
   */
  getCapabilities() {
    const capabilities = {};

    for (const [name, integration] of this.integrations) {
      capabilities[name] = {
        sendEvent: typeof integration.sendEvent === 'function',
        sendBatchEvents: typeof integration.sendBatchEvents === 'function',
        queryEvents: typeof integration.queryEvents === 'function',
        createAlert: typeof integration.createAlert === 'function',
        getDashboards: typeof integration.getDashboards === 'function',
        getSavedSearches: typeof integration.getSavedSearches === 'function',
        healthCheck: typeof integration.healthCheck === 'function',
      };
    }

    return capabilities;
  }

  /**
   * Get all active integrations
   */
  getActiveIntegrations() {
    return Array.from(this.integrations.keys());
  }

  /**
   * Get health status
   */
  getHealthStatus() {
    return {
      lastCheck: this.lastHealthCheck,
      integrations: Object.fromEntries(this.healthStatus),
      bufferSize: this.eventBuffer.length,
      maxBufferSize: this.maxBufferSize,
    };
  }
}

module.exports = new SIEMIntegrationManager();