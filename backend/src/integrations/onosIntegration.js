/**
 * ONOS SDN Controller Integration
 * Provides integration with ONOS (Open Network Operating System) controller
 */

const axios = require('axios');
const logger = require('../config/logger');

class ONOSIntegration {
  constructor(config) {
    this.config = config;
    this.baseUrl = `${config.protocol}://${config.hostname}:${config.port}`;
    this.auth = {
      username: config.username,
      password: config.password,
    };
    this.httpClient = this.createHttpClient();
  }

  /**
   * Create HTTP client with authentication
   */
  createHttpClient() {
    return axios.create({
      baseURL: this.baseUrl,
      auth: this.auth,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    });
  }

  /**
   * Initialize the integration
   */
  async initialize() {
    try {
      logger.info('Initializing ONOS integration...');
      
      // Test connectivity
      await this.healthCheck();
      
      logger.info('ONOS integration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize ONOS integration:', error);
      throw error;
    }
  }

  /**
   * Block an IP address by creating a flow rule
   */
  async blockIP(ipAddress, options = {}) {
    try {
      const flowRule = {
        priority: options.priority || 40000,
        timeout: options.timeout || 0,
        isPermanent: options.permanent !== false,
        deviceId: options.deviceId || await this.getDefaultDevice(),
        treatment: {
          instructions: [] // Empty instructions = drop
        },
        selector: {
          criteria: [
            {
              type: 'ETH_TYPE',
              ethType: '0x0800' // IPv4
            },
            {
              type: 'IPV4_SRC',
              ip: ipAddress
            }
          ]
        }
      };

      const response = await this.httpClient.post('/onos/v1/flows', flowRule);
      
      logger.info(`Blocked IP ${ipAddress} on ONOS controller`);
      return {
        success: true,
        flowId: response.data.id || `autosec-block-${ipAddress}`,
        deviceId: flowRule.deviceId,
        response: response.status
      };
    } catch (error) {
      logger.error(`Failed to block IP ${ipAddress} on ONOS:`, error);
      throw error;
    }
  }

  /**
   * Unblock an IP address by removing flow rules
   */
  async unblockIP(ipAddress, options = {}) {
    try {
      // Get all flows and filter for those blocking this IP
      const devices = await this.getDevices();
      const results = [];

      for (const device of devices) {
        try {
          const flows = await this.getFlowsForDevice(device.id);
          const blockingFlows = flows.filter(flow => 
            flow.selector && 
            flow.selector.criteria &&
            flow.selector.criteria.some(criteria => 
              criteria.type === 'IPV4_SRC' && criteria.ip === ipAddress
            ) &&
            (!flow.treatment.instructions || flow.treatment.instructions.length === 0)
          );

          for (const flow of blockingFlows) {
            await this.httpClient.delete(`/onos/v1/flows/${device.id}/${flow.id}`);
            results.push({
              deviceId: device.id,
              flowId: flow.id,
              success: true
            });
          }
        } catch (error) {
          logger.error(`Failed to remove flows from device ${device.id}:`, error);
          results.push({
            deviceId: device.id,
            success: false,
            error: error.message
          });
        }
      }

      logger.info(`Unblocked IP ${ipAddress} on ONOS controller`);
      return { success: true, results };
    } catch (error) {
      logger.error(`Failed to unblock IP ${ipAddress} on ONOS:`, error);
      throw error;
    }
  }

  /**
   * Create a custom flow rule
   */
  async createFlowRule(ruleConfig) {
    try {
      const flowRule = this.buildFlowRule(ruleConfig);
      
      const response = await this.httpClient.post('/onos/v1/flows', flowRule);

      logger.info(`Created flow rule on ONOS controller`);
      return {
        success: true,
        flowId: response.data.id,
        deviceId: flowRule.deviceId,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to create flow rule on ONOS:', error);
      throw error;
    }
  }

  /**
   * Get network topology
   */
  async getTopology() {
    try {
      const [devices, links, hosts] = await Promise.all([
        this.getDevices(),
        this.getLinks(),
        this.getHosts()
      ]);

      return {
        devices,
        links,
        hosts,
        timestamp: Date.now(),
        controller: 'onos'
      };
    } catch (error) {
      logger.error('Failed to get topology from ONOS:', error);
      throw error;
    }
  }

  /**
   * Get flow statistics
   */
  async getFlowStatistics(filters = {}) {
    try {
      const devices = await this.getDevices();
      const statistics = {};

      for (const device of devices) {
        try {
          const flows = await this.getFlowsForDevice(device.id);
          statistics[device.id] = {
            flows,
            flowCount: flows.length,
            timestamp: Date.now()
          };
        } catch (error) {
          logger.error(`Failed to get statistics for device ${device.id}:`, error);
          statistics[device.id] = { error: error.message };
        }
      }

      return statistics;
    } catch (error) {
      logger.error('Failed to get flow statistics from ONOS:', error);
      throw error;
    }
  }

  /**
   * Get all devices in the network
   */
  async getDevices() {
    try {
      const response = await this.httpClient.get('/onos/v1/devices');
      return response.data.devices || [];
    } catch (error) {
      logger.error('Failed to get devices from ONOS:', error);
      return [];
    }
  }

  /**
   * Get all links in the network
   */
  async getLinks() {
    try {
      const response = await this.httpClient.get('/onos/v1/links');
      return response.data.links || [];
    } catch (error) {
      logger.error('Failed to get links from ONOS:', error);
      return [];
    }
  }

  /**
   * Get all hosts in the network
   */
  async getHosts() {
    try {
      const response = await this.httpClient.get('/onos/v1/hosts');
      return response.data.hosts || [];
    } catch (error) {
      logger.error('Failed to get hosts from ONOS:', error);
      return [];
    }
  }

  /**
   * Get flows for a specific device
   */
  async getFlowsForDevice(deviceId) {
    try {
      const response = await this.httpClient.get(`/onos/v1/flows/${deviceId}`);
      return response.data.flows || [];
    } catch (error) {
      logger.error(`Failed to get flows for device ${deviceId}:`, error);
      return [];
    }
  }

  /**
   * Get default device for flow installation
   */
  async getDefaultDevice() {
    try {
      const devices = await this.getDevices();
      return devices.length > 0 ? devices[0].id : 'of:0000000000000001';
    } catch (error) {
      logger.error('Failed to get default device:', error);
      return 'of:0000000000000001';
    }
  }

  /**
   * Build a flow rule from configuration
   */
  buildFlowRule(config) {
    return {
      priority: config.priority || 40000,
      timeout: config.timeout || 0,
      isPermanent: config.permanent !== false,
      deviceId: config.deviceId || config.device,
      appId: config.appId || 'org.onosproject.autosec',
      treatment: {
        instructions: config.instructions || config.actions || []
      },
      selector: {
        criteria: config.criteria || config.match || []
      }
    };
  }

  /**
   * Install an application if not already installed
   */
  async installApp(appName) {
    try {
      const response = await this.httpClient.post(`/onos/v1/applications/${appName}/active`);
      logger.info(`Installed/activated ONOS application: ${appName}`);
      return response.status === 200;
    } catch (error) {
      logger.error(`Failed to install ONOS application ${appName}:`, error);
      return false;
    }
  }

  /**
   * Get application status
   */
  async getAppStatus(appName) {
    try {
      const response = await this.httpClient.get(`/onos/v1/applications/${appName}`);
      return response.data;
    } catch (error) {
      logger.error(`Failed to get status for ONOS application ${appName}:`, error);
      return null;
    }
  }

  /**
   * Perform health check
   */
  async healthCheck() {
    try {
      const response = await this.httpClient.get('/onos/v1/devices');
      return response.status === 200;
    } catch (error) {
      logger.error('ONOS health check failed:', error);
      return false;
    }
  }

  /**
   * Get integration info
   */
  getInfo() {
    return {
      type: 'onos',
      baseUrl: this.baseUrl,
      status: 'connected'
    };
  }
}

module.exports = ONOSIntegration;