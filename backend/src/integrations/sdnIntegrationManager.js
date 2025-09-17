/**
 * SDN Controller Integration Manager
 * Manages integrations with Software-Defined Network controllers
 */

const OpenDaylightIntegration = require('./openDaylightIntegration');
const ONOSIntegration = require('./onosIntegration');
const logger = require('../config/logger');

class SDNIntegrationManager {
  constructor() {
    this.integrations = new Map();
    this.config = this.loadConfiguration();
    this.healthStatus = new Map();
    this.lastHealthCheck = null;
  }

  /**
   * Load SDN controller configurations from environment
   */
  loadConfiguration() {
    return {
      opendaylight: {
        enabled: process.env.OPENDAYLIGHT_ENABLED === 'true',
        hostname: process.env.OPENDAYLIGHT_HOST,
        port: process.env.OPENDAYLIGHT_PORT || 8181,
        username: process.env.OPENDAYLIGHT_USERNAME || 'admin',
        password: process.env.OPENDAYLIGHT_PASSWORD || 'admin',
        protocol: process.env.OPENDAYLIGHT_PROTOCOL || 'http',
      },
      onos: {
        enabled: process.env.ONOS_ENABLED === 'true',
        hostname: process.env.ONOS_HOST,
        port: process.env.ONOS_PORT || 8181,
        username: process.env.ONOS_USERNAME || 'onos',
        password: process.env.ONOS_PASSWORD || 'rocks',
        protocol: process.env.ONOS_PROTOCOL || 'http',
      },
    };
  }

  /**
   * Initialize all enabled SDN integrations
   */
  async initialize() {
    try {
      logger.info('Initializing SDN integrations...');

      // Initialize OpenDaylight
      if (this.config.opendaylight.enabled) {
        await this.initializeIntegration('opendaylight', new OpenDaylightIntegration(this.config.opendaylight));
      }

      // Initialize ONOS
      if (this.config.onos.enabled) {
        await this.initializeIntegration('onos', new ONOSIntegration(this.config.onos));
      }

      logger.info(`SDN integrations initialized: ${Array.from(this.integrations.keys()).join(', ')}`);
    } catch (error) {
      logger.error('Error initializing SDN integrations:', error);
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
      logger.info(`SDN integration '${name}' initialized successfully`);
    } catch (error) {
      logger.error(`Failed to initialize SDN integration '${name}':`, error);
      this.healthStatus.set(name, { status: 'error', error: error.message, lastCheck: Date.now() });
      throw error;
    }
  }

  /**
   * Block traffic from an IP address across all SDN controllers
   */
  async blockIP(ipAddress, options = {}) {
    const results = [];
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.info(`Blocking IP ${ipAddress} on SDN controller: ${name}`);
        const result = await integration.blockIP(ipAddress, options);
        results.push({ integration: name, success: true, result });
      } catch (error) {
        logger.error(`Failed to block IP ${ipAddress} on ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Unblock traffic from an IP address across all SDN controllers
   */
  async unblockIP(ipAddress, options = {}) {
    const results = [];
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.info(`Unblocking IP ${ipAddress} on SDN controller: ${name}`);
        const result = await integration.unblockIP(ipAddress, options);
        results.push({ integration: name, success: true, result });
      } catch (error) {
        logger.error(`Failed to unblock IP ${ipAddress} on ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Create a flow rule across specified SDN controllers
   */
  async createFlowRule(ruleConfig, targets = null) {
    const targetIntegrations = targets ? 
      Array.from(this.integrations.entries()).filter(([name]) => targets.includes(name)) :
      Array.from(this.integrations.entries());

    const results = [];
    const errors = [];

    for (const [name, integration] of targetIntegrations) {
      try {
        logger.info(`Creating flow rule on SDN controller: ${name}`);
        const result = await integration.createFlowRule(ruleConfig);
        results.push({ integration: name, success: true, result });
      } catch (error) {
        logger.error(`Failed to create flow rule on ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Get network topology from all SDN controllers
   */
  async getNetworkTopology() {
    const topologies = {};
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Fetching topology from SDN controller: ${name}`);
        const topology = await integration.getTopology();
        topologies[name] = topology;
      } catch (error) {
        logger.error(`Failed to get topology from ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { topologies, errors };
  }

  /**
   * Get flow statistics from all SDN controllers
   */
  async getFlowStatistics(filters = {}) {
    const statistics = {};
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Fetching flow statistics from SDN controller: ${name}`);
        const stats = await integration.getFlowStatistics(filters);
        statistics[name] = stats;
      } catch (error) {
        logger.error(`Failed to get flow statistics from ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { statistics, errors };
  }

  /**
   * Perform health check on all integrations
   */
  async performHealthCheck() {
    logger.info('Performing SDN integration health check...');
    this.lastHealthCheck = Date.now();

    for (const [name, integration] of this.integrations) {
      try {
        const isHealthy = await integration.healthCheck();
        this.healthStatus.set(name, {
          status: isHealthy ? 'healthy' : 'unhealthy',
          lastCheck: this.lastHealthCheck,
        });
      } catch (error) {
        logger.error(`Health check failed for SDN integration '${name}':`, error);
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
        blockIP: typeof integration.blockIP === 'function',
        unblockIP: typeof integration.unblockIP === 'function',
        createFlowRule: typeof integration.createFlowRule === 'function',
        getTopology: typeof integration.getTopology === 'function',
        getFlowStatistics: typeof integration.getFlowStatistics === 'function',
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
    };
  }
}

module.exports = new SDNIntegrationManager();