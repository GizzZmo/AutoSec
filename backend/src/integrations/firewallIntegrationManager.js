/**
 * Firewall Integration Manager
 * Coordinates and manages multiple firewall integrations
 */

const PaloAltoIntegration = require('./paloAltoIntegration');
const CiscoASAIntegration = require('./ciscoASAIntegration');
const IptablesIntegration = require('./iptablesIntegration');
const logger = require('../config/logger');

class FirewallIntegrationManager {
  constructor() {
    this.integrations = new Map();
    this.config = this.loadConfiguration();
    this.healthStatus = new Map();
    this.lastHealthCheck = null;
    this.ruleCache = new Map();
  }

  /**
   * Load firewall configurations from environment or config
   */
  loadConfiguration() {
    return {
      paloAlto: {
        enabled: process.env.PALO_ALTO_ENABLED === 'true',
        hostname: process.env.PALO_ALTO_HOST,
        username: process.env.PALO_ALTO_USERNAME,
        password: process.env.PALO_ALTO_PASSWORD,
        apiKey: process.env.PALO_ALTO_API_KEY,
        port: process.env.PALO_ALTO_PORT || 443,
        vsys: process.env.PALO_ALTO_VSYS || 'vsys1',
        deviceGroup: process.env.PALO_ALTO_DEVICE_GROUP,
      },
      ciscoASA: {
        enabled: process.env.CISCO_ASA_ENABLED === 'true',
        hostname: process.env.CISCO_ASA_HOST,
        username: process.env.CISCO_ASA_USERNAME,
        password: process.env.CISCO_ASA_PASSWORD,
        port: process.env.CISCO_ASA_PORT || 443,
        deviceType: process.env.CISCO_ASA_DEVICE_TYPE || 'asa',
        apiVersion: process.env.CISCO_ASA_API_VERSION || 'v1',
      },
      iptables: {
        enabled: process.env.IPTABLES_ENABLED !== 'false', // Enabled by default on Linux
        sudo: process.env.IPTABLES_SUDO !== 'false',
        customChain: process.env.IPTABLES_CHAIN || 'AUTOSEC',
        backupPath: process.env.IPTABLES_BACKUP_PATH || '/tmp/autosec-iptables-backup',
      },
    };
  }

  /**
   * Initialize all enabled firewall integrations
   */
  async initialize() {
    try {
      logger.info('Initializing firewall integrations...');

      const initPromises = [];

      // Initialize Palo Alto
      if (this.config.paloAlto.enabled && this.config.paloAlto.hostname) {
        const paloAlto = new PaloAltoIntegration(this.config.paloAlto);
        this.integrations.set('paloAlto', paloAlto);
        initPromises.push(this.initializeIntegration('paloAlto', paloAlto));
      }

      // Initialize Cisco ASA/FTD
      if (this.config.ciscoASA.enabled && this.config.ciscoASA.hostname) {
        const ciscoASA = new CiscoASAIntegration(this.config.ciscoASA);
        this.integrations.set('ciscoASA', ciscoASA);
        initPromises.push(this.initializeIntegration('ciscoASA', ciscoASA));
      }

      // Initialize iptables
      if (this.config.iptables.enabled) {
        const iptables = new IptablesIntegration(this.config.iptables);
        this.integrations.set('iptables', iptables);
        initPromises.push(this.initializeIntegration('iptables', iptables));
      }

      // Wait for all initializations
      const results = await Promise.allSettled(initPromises);

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      logger.info('Firewall integrations initialization completed', {
        total: results.length,
        successful,
        failed,
        enabledIntegrations: Array.from(this.integrations.keys()),
      });

      // Start health monitoring
      this.startHealthMonitoring();

      return {
        success: true,
        totalIntegrations: results.length,
        successfulIntegrations: successful,
        failedIntegrations: failed,
        enabledIntegrations: Array.from(this.integrations.keys()),
      };
    } catch (error) {
      logger.error('Error initializing firewall integrations:', error);
      throw error;
    }
  }

  /**
   * Initialize a specific integration
   */
  async initializeIntegration(name, integration) {
    try {
      logger.info(`Initializing ${name} integration...`);

      let result;
      if (name === 'iptables') {
        result = await integration.initialize();
      } else {
        result = await integration.testConnection();
      }

      if (result.success) {
        this.healthStatus.set(name, {
          status: 'healthy',
          lastCheck: new Date(),
          ...result,
        });
        logger.info(`${name} integration initialized successfully`);
      } else {
        throw new Error(result.error || 'Initialization failed');
      }

      return result;
    } catch (error) {
      this.healthStatus.set(name, {
        status: 'unhealthy',
        lastCheck: new Date(),
        error: error.message,
      });
      logger.error(`Failed to initialize ${name} integration:`, error);
      throw error;
    }
  }

  /**
   * Block an IP address across all integrations
   */
  async blockIP(ipAddress, options = {}) {
    const {
      reason = 'AutoSec Security Block',
      targets = Array.from(this.integrations.keys()),
      timeout = 30000,
      duration = null,
    } = options;

    logger.info(`Blocking IP ${ipAddress} across integrations`, {
      targets,
      reason,
      duration,
    });

    const results = new Map();
    const promises = targets.map(async (target) => {
      const integration = this.integrations.get(target);
      if (!integration) {
        results.set(target, {
          success: false,
          error: 'Integration not available',
        });
        return;
      }

      try {
        const startTime = Date.now();
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Timeout')), timeout)
        );

        let blockPromise;
        if (target === 'iptables') {
          blockPromise = integration.blockIP(ipAddress, reason, duration);
        } else {
          blockPromise = integration.blockIP(ipAddress, reason);
        }

        const result = await Promise.race([blockPromise, timeoutPromise]);
        const executionTime = Date.now() - startTime;

        results.set(target, {
          ...result,
          executionTime,
        });

        logger.info(`Successfully blocked IP on ${target}`, {
          ipAddress,
          executionTime,
        });
      } catch (error) {
        results.set(target, {
          success: false,
          error: error.message,
          target,
        });

        logger.error(`Failed to block IP on ${target}:`, error);
      }
    });

    await Promise.allSettled(promises);

    // Update rule cache
    this.updateRuleCache('block', ipAddress, reason, results);

    const successful = Array.from(results.values()).filter(r => r.success).length;
    const failed = results.size - successful;

    logger.info(`IP blocking completed`, {
      ipAddress,
      totalTargets: results.size,
      successful,
      failed,
    });

    return {
      ipAddress,
      action: 'block',
      results: Object.fromEntries(results),
      summary: {
        total: results.size,
        successful,
        failed,
        successRate: (successful / results.size) * 100,
      },
      timestamp: new Date(),
    };
  }

  /**
   * Unblock an IP address across all integrations
   */
  async unblockIP(ipAddress, options = {}) {
    const {
      targets = Array.from(this.integrations.keys()),
      timeout = 30000,
    } = options;

    logger.info(`Unblocking IP ${ipAddress} across integrations`, {
      targets,
    });

    const results = new Map();
    const promises = targets.map(async (target) => {
      const integration = this.integrations.get(target);
      if (!integration) {
        results.set(target, {
          success: false,
          error: 'Integration not available',
        });
        return;
      }

      try {
        const startTime = Date.now();
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Timeout')), timeout)
        );

        const result = await Promise.race([
          integration.unblockIP(ipAddress),
          timeoutPromise,
        ]);

        const executionTime = Date.now() - startTime;

        results.set(target, {
          ...result,
          executionTime,
        });

        logger.info(`Successfully unblocked IP on ${target}`, {
          ipAddress,
          executionTime,
        });
      } catch (error) {
        results.set(target, {
          success: false,
          error: error.message,
          target,
        });

        logger.error(`Failed to unblock IP on ${target}:`, error);
      }
    });

    await Promise.allSettled(promises);

    // Update rule cache
    this.updateRuleCache('unblock', ipAddress, null, results);

    const successful = Array.from(results.values()).filter(r => r.success).length;
    const failed = results.size - successful;

    logger.info(`IP unblocking completed`, {
      ipAddress,
      totalTargets: results.size,
      successful,
      failed,
    });

    return {
      ipAddress,
      action: 'unblock',
      results: Object.fromEntries(results),
      summary: {
        total: results.size,
        successful,
        failed,
        successRate: (successful / results.size) * 100,
      },
      timestamp: new Date(),
    };
  }

  /**
   * Create a security rule across specified integrations
   */
  async createSecurityRule(ruleConfig, targets = null) {
    const targetIntegrations = targets || Array.from(this.integrations.keys());

    logger.info('Creating security rule across integrations', {
      targets: targetIntegrations,
      rule: ruleConfig,
    });

    const results = new Map();
    const promises = targetIntegrations.map(async (target) => {
      const integration = this.integrations.get(target);
      if (!integration || !integration.createSecurityRule) {
        results.set(target, {
          success: false,
          error: 'Rule creation not supported',
        });
        return;
      }

      try {
        const result = await integration.createSecurityRule(ruleConfig);
        results.set(target, result);
        logger.info(`Successfully created rule on ${target}`);
      } catch (error) {
        results.set(target, {
          success: false,
          error: error.message,
        });
        logger.error(`Failed to create rule on ${target}:`, error);
      }
    });

    await Promise.allSettled(promises);

    const successful = Array.from(results.values()).filter(r => r.success).length;

    return {
      ruleConfig,
      results: Object.fromEntries(results),
      summary: {
        total: results.size,
        successful,
        failed: results.size - successful,
      },
      timestamp: new Date(),
    };
  }

  /**
   * Get logs from all integrations
   */
  async getAllLogs(filters = {}) {
    const allLogs = new Map();

    for (const [name, integration] of this.integrations) {
      try {
        let logs = [];

        if (name === 'paloAlto' && integration.getThreatLogs) {
          logs = await integration.getThreatLogs(filters);
        } else if (name === 'ciscoASA' && integration.getConnectionLogs) {
          logs = await integration.getConnectionLogs(filters);
        } else if (name === 'iptables' && integration.getFirewallLogs) {
          logs = await integration.getFirewallLogs(filters);
        }

        allLogs.set(name, logs);
        logger.info(`Retrieved logs from ${name}`, { count: logs.length });
      } catch (error) {
        logger.error(`Error retrieving logs from ${name}:`, error);
        allLogs.set(name, []);
      }
    }

    return Object.fromEntries(allLogs);
  }

  /**
   * Get system information from all integrations
   */
  async getAllSystemInfo() {
    const systemInfo = new Map();

    for (const [name, integration] of this.integrations) {
      try {
        const info = await integration.getSystemInfo();
        systemInfo.set(name, info);
      } catch (error) {
        logger.error(`Error getting system info from ${name}:`, error);
        systemInfo.set(name, { error: error.message });
      }
    }

    return Object.fromEntries(systemInfo);
  }

  /**
   * Start health monitoring for all integrations
   */
  startHealthMonitoring() {
    const checkInterval = 5 * 60 * 1000; // 5 minutes

    setInterval(async () => {
      await this.performHealthCheck();
    }, checkInterval);

    logger.info('Started health monitoring for firewall integrations');
  }

  /**
   * Perform health check on all integrations
   */
  async performHealthCheck() {
    logger.debug('Performing health check on firewall integrations');

    for (const [name, integration] of this.integrations) {
      try {
        const result = await integration.testConnection();
        
        this.healthStatus.set(name, {
          status: result.success ? 'healthy' : 'unhealthy',
          lastCheck: new Date(),
          ...result,
        });
      } catch (error) {
        this.healthStatus.set(name, {
          status: 'unhealthy',
          lastCheck: new Date(),
          error: error.message,
        });
      }
    }

    this.lastHealthCheck = new Date();
  }

  /**
   * Get health status of all integrations
   */
  getHealthStatus() {
    return {
      status: Object.fromEntries(this.healthStatus),
      lastHealthCheck: this.lastHealthCheck,
      enabledIntegrations: Array.from(this.integrations.keys()),
      summary: {
        total: this.healthStatus.size,
        healthy: Array.from(this.healthStatus.values()).filter(s => s.status === 'healthy').length,
        unhealthy: Array.from(this.healthStatus.values()).filter(s => s.status === 'unhealthy').length,
      },
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
        createRule: typeof integration.createSecurityRule === 'function' || 
                   typeof integration.createRule === 'function',
        getLogs: typeof integration.getThreatLogs === 'function' || 
                typeof integration.getConnectionLogs === 'function' ||
                typeof integration.getFirewallLogs === 'function',
        getSystemInfo: typeof integration.getSystemInfo === 'function',
      };
    }

    return capabilities;
  }

  /**
   * Update rule cache for tracking
   */
  updateRuleCache(action, ipAddress, reason, results) {
    const key = `${action}_${ipAddress}`;
    this.ruleCache.set(key, {
      action,
      ipAddress,
      reason,
      results: Object.fromEntries(results),
      timestamp: new Date(),
    });

    // Cleanup old cache entries (keep last 1000)
    if (this.ruleCache.size > 1000) {
      const oldestKey = this.ruleCache.keys().next().value;
      this.ruleCache.delete(oldestKey);
    }
  }

  /**
   * Get recent rule history
   */
  getRuleHistory(limit = 100) {
    const entries = Array.from(this.ruleCache.values())
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit);

    return entries;
  }

  /**
   * Get specific integration
   */
  getIntegration(name) {
    return this.integrations.get(name);
  }

  /**
   * Check if integration is available and healthy
   */
  isIntegrationAvailable(name) {
    const integration = this.integrations.get(name);
    const health = this.healthStatus.get(name);
    
    return integration && health && health.status === 'healthy';
  }

  /**
   * Bulk operations for multiple IPs
   */
  async bulkBlockIPs(ipAddresses, options = {}) {
    const results = {};

    for (const ip of ipAddresses) {
      try {
        results[ip] = await this.blockIP(ip, options);
      } catch (error) {
        results[ip] = {
          success: false,
          error: error.message,
          ipAddress: ip,
        };
      }
    }

    return results;
  }

  async bulkUnblockIPs(ipAddresses, options = {}) {
    const results = {};

    for (const ip of ipAddresses) {
      try {
        results[ip] = await this.unblockIP(ip, options);
      } catch (error) {
        results[ip] = {
          success: false,
          error: error.message,
          ipAddress: ip,
        };
      }
    }

    return results;
  }
}

module.exports = new FirewallIntegrationManager();