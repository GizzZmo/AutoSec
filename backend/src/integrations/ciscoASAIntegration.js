/**
 * Cisco ASA/FTD Firewall Integration
 * Provides integration with Cisco ASA and FTD via REST API and SSH
 */

const axios = require('axios');
const { Client } = require('ssh2');
const logger = require('../config/logger');

class CiscoASAIntegration {
  constructor(config) {
    this.config = {
      hostname: config.hostname,
      username: config.username,
      password: config.password,
      port: config.port || 443,
      sshPort: config.sshPort || 22,
      timeout: config.timeout || 30000,
      deviceType: config.deviceType || 'asa', // 'asa' or 'ftd'
      apiVersion: config.apiVersion || 'v1',
    };
    
    this.authToken = null;
    this.sessionTimeout = null;
    this.sshConnection = null;
  }

  /**
   * Authenticate with the Cisco ASA/FTD
   */
  async authenticate() {
    try {
      if (this.config.deviceType === 'ftd') {
        return this.authenticateFTD();
      } else {
        return this.authenticateASA();
      }
    } catch (error) {
      logger.error('Error authenticating with Cisco ASA/FTD:', error);
      throw error;
    }
  }

  /**
   * Authenticate with Cisco ASA via REST API
   */
  async authenticateASA() {
    try {
      const response = await this.makeRequest('POST', '/api/tokenservices', {
        username: this.config.username,
        password: this.config.password,
      });

      this.authToken = response.headers['x-auth-token'];
      this.sessionTimeout = Date.now() + (30 * 60 * 1000); // 30 minutes

      logger.info('Successfully authenticated with Cisco ASA', {
        hostname: this.config.hostname,
      });

      return true;
    } catch (error) {
      logger.error('Error authenticating with Cisco ASA:', error);
      throw error;
    }
  }

  /**
   * Authenticate with Cisco FTD via FMC
   */
  async authenticateFTD() {
    try {
      const response = await this.makeRequest('POST', '/api/fmc_platform/v1/auth/generatetoken', {}, {
        Authorization: `Basic ${Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64')}`,
      });

      this.authToken = response.headers['x-auth-access-token'];
      this.refreshToken = response.headers['x-auth-refresh-token'];
      this.sessionTimeout = Date.now() + (30 * 60 * 1000); // 30 minutes

      logger.info('Successfully authenticated with Cisco FTD', {
        hostname: this.config.hostname,
      });

      return true;
    } catch (error) {
      logger.error('Error authenticating with Cisco FTD:', error);
      throw error;
    }
  }

  /**
   * Block an IP address
   */
  async blockIP(ipAddress, reason = 'AutoSec Security Block') {
    try {
      await this.ensureAuthenticated();

      if (this.config.deviceType === 'ftd') {
        return this.blockIPFTD(ipAddress, reason);
      } else {
        return this.blockIPASA(ipAddress, reason);
      }
    } catch (error) {
      logger.error('Error blocking IP address:', error);
      throw error;
    }
  }

  /**
   * Block IP on Cisco ASA
   */
  async blockIPASA(ipAddress, reason) {
    const objectName = `AutoSec_Block_${ipAddress.replace(/\./g, '_')}`;
    
    // Create network object
    await this.createNetworkObject(objectName, ipAddress, reason);
    
    // Add to access rule
    await this.addToAccessRule(objectName, 'deny');

    logger.info('Successfully blocked IP on ASA', {
      ipAddress,
      objectName,
      reason,
    });

    return {
      success: true,
      ipAddress,
      objectName,
      action: 'blocked',
      device: 'asa',
      timestamp: new Date(),
    };
  }

  /**
   * Block IP on Cisco FTD
   */
  async blockIPFTD(ipAddress, reason) {
    const objectName = `AutoSec_Block_${ipAddress.replace(/\./g, '_')}`;
    
    // Create host object
    const hostObject = await this.createHostObjectFTD(objectName, ipAddress, reason);
    
    // Add to access policy
    await this.addToAccessPolicyFTD(hostObject.id, 'BLOCK');

    logger.info('Successfully blocked IP on FTD', {
      ipAddress,
      objectName,
      reason,
    });

    return {
      success: true,
      ipAddress,
      objectName,
      action: 'blocked',
      device: 'ftd',
      timestamp: new Date(),
    };
  }

  /**
   * Unblock an IP address
   */
  async unblockIP(ipAddress) {
    try {
      await this.ensureAuthenticated();

      const objectName = `AutoSec_Block_${ipAddress.replace(/\./g, '_')}`;

      if (this.config.deviceType === 'ftd') {
        await this.removeFromAccessPolicyFTD(objectName);
        await this.deleteHostObjectFTD(objectName);
      } else {
        await this.removeFromAccessRule(objectName);
        await this.deleteNetworkObject(objectName);
      }

      logger.info('Successfully unblocked IP address', {
        ipAddress,
        objectName,
      });

      return {
        success: true,
        ipAddress,
        objectName,
        action: 'unblocked',
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error unblocking IP address:', error);
      throw error;
    }
  }

  /**
   * Create access rule
   */
  async createAccessRule(ruleConfig) {
    try {
      await this.ensureAuthenticated();

      if (this.config.deviceType === 'ftd') {
        return this.createAccessRuleFTD(ruleConfig);
      } else {
        return this.createAccessRuleASA(ruleConfig);
      }
    } catch (error) {
      logger.error('Error creating access rule:', error);
      throw error;
    }
  }

  /**
   * Get system information
   */
  async getSystemInfo() {
    try {
      await this.ensureAuthenticated();

      if (this.config.deviceType === 'ftd') {
        return this.getSystemInfoFTD();
      } else {
        return this.getSystemInfoASA();
      }
    } catch (error) {
      logger.error('Error getting system info:', error);
      throw error;
    }
  }

  /**
   * Get ASA system information
   */
  async getSystemInfoASA() {
    const response = await this.makeAuthenticatedRequest('GET', '/api/monitoring/device');
    const deviceInfo = response.data;

    return {
      hostname: deviceInfo.hostname,
      model: deviceInfo.model,
      version: deviceInfo.version,
      serial: deviceInfo.serial,
      uptime: deviceInfo.uptime,
      interfaces: deviceInfo.interfaces,
    };
  }

  /**
   * Get FTD system information
   */
  async getSystemInfoFTD() {
    const response = await this.makeAuthenticatedRequest('GET', '/api/fmc_platform/v1/info/serverversion');
    const serverInfo = response.data;

    return {
      hostname: this.config.hostname,
      version: serverInfo.serverVersion,
      buildNumber: serverInfo.buildNumber,
      releaseDate: serverInfo.releaseDate,
    };
  }

  /**
   * SSH-based operations for older ASA devices
   */
  async executeSSHCommand(command) {
    return new Promise((resolve, reject) => {
      const conn = new Client();
      
      conn.on('ready', () => {
        conn.exec(command, (err, stream) => {
          if (err) {
            conn.end();
            return reject(err);
          }

          let output = '';
          let error = '';

          stream.on('close', (code, signal) => {
            conn.end();
            if (code === 0) {
              resolve(output);
            } else {
              reject(new Error(`Command failed with code ${code}: ${error}`));
            }
          });

          stream.on('data', (data) => {
            output += data.toString();
          });

          stream.stderr.on('data', (data) => {
            error += data.toString();
          });
        });
      });

      conn.on('error', (err) => {
        reject(err);
      });

      conn.connect({
        host: this.config.hostname,
        port: this.config.sshPort,
        username: this.config.username,
        password: this.config.password,
        timeout: this.config.timeout,
      });
    });
  }

  /**
   * Helper methods for ASA
   */
  async createNetworkObject(name, ipAddress, description) {
    const objectData = {
      name,
      value: `${ipAddress}/32`,
      description,
      objectType: 'IPv4Address',
    };

    await this.makeAuthenticatedRequest('POST', '/api/objects/networkobjects', objectData);
  }

  async deleteNetworkObject(name) {
    // First get the object to find its ID
    const response = await this.makeAuthenticatedRequest('GET', `/api/objects/networkobjects/${name}`);
    const objectId = response.data.objectId;

    await this.makeAuthenticatedRequest('DELETE', `/api/objects/networkobjects/${objectId}`);
  }

  async addToAccessRule(objectName, action) {
    const ruleData = {
      sourceAddress: {
        objectType: 'NetworkObject',
        name: objectName,
      },
      destinationAddress: {
        objectType: 'AnyAddress',
      },
      sourceService: {
        objectType: 'AnyService',
      },
      destinationService: {
        objectType: 'AnyService',
      },
      action,
      isEnabled: true,
      remarks: 'AutoSec generated rule',
    };

    await this.makeAuthenticatedRequest('POST', '/api/access/rules', ruleData);
  }

  async removeFromAccessRule(objectName) {
    // Find and remove rules containing this object
    const response = await this.makeAuthenticatedRequest('GET', '/api/access/rules');
    const rules = response.data.items || [];

    for (const rule of rules) {
      if (rule.sourceAddress?.name === objectName) {
        await this.makeAuthenticatedRequest('DELETE', `/api/access/rules/${rule.objectId}`);
      }
    }
  }

  /**
   * Helper methods for FTD
   */
  async createHostObjectFTD(name, ipAddress, description) {
    const objectData = {
      name,
      type: 'Host',
      value: ipAddress,
      description,
    };

    const response = await this.makeAuthenticatedRequest('POST', '/api/fmc_config/v1/domain/default/object/hosts', objectData);
    return response.data;
  }

  async deleteHostObjectFTD(name) {
    // First get the object to find its ID
    const response = await this.makeAuthenticatedRequest('GET', `/api/fmc_config/v1/domain/default/object/hosts/${name}`);
    const objectId = response.data.id;

    await this.makeAuthenticatedRequest('DELETE', `/api/fmc_config/v1/domain/default/object/hosts/${objectId}`);
  }

  async addToAccessPolicyFTD(objectId, action) {
    // This is a simplified implementation
    // In practice, you'd need to find the appropriate access policy and add a rule
    const ruleData = {
      name: `AutoSec_Block_Rule_${Date.now()}`,
      action,
      sourceNetworks: [{ id: objectId }],
      enabled: true,
    };

    // This would need the actual access policy ID
    const policyId = 'default-access-policy';
    await this.makeAuthenticatedRequest('POST', `/api/fmc_config/v1/domain/default/policy/accesspolicies/${policyId}/accessrules`, ruleData);
  }

  async removeFromAccessPolicyFTD(objectName) {
    // Find and remove rules containing this object
    // Implementation would depend on specific FTD setup
  }

  /**
   * Core HTTP request methods
   */
  async ensureAuthenticated() {
    if (!this.authToken || (this.sessionTimeout && Date.now() > this.sessionTimeout)) {
      await this.authenticate();
    }
  }

  async makeAuthenticatedRequest(method, path, data = null) {
    await this.ensureAuthenticated();

    const headers = {};
    
    if (this.config.deviceType === 'ftd') {
      headers['X-auth-access-token'] = this.authToken;
    } else {
      headers['X-auth-token'] = this.authToken;
    }

    return this.makeRequest(method, path, data, headers);
  }

  async makeRequest(method, path, data = null, additionalHeaders = {}) {
    const baseURL = this.config.deviceType === 'ftd' ? 
      `https://${this.config.hostname}:${this.config.port}` :
      `https://${this.config.hostname}:${this.config.port}`;

    const config = {
      method,
      url: `${baseURL}${path}`,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...additionalHeaders,
      },
      httpsAgent: new (require('https').Agent)({
        rejectUnauthorized: false,
      }),
    };

    if (data) {
      config.data = data;
    }

    try {
      const response = await axios(config);
      return response;
    } catch (error) {
      if (error.response) {
        logger.error('API request failed:', {
          status: error.response.status,
          data: error.response.data,
        });
      }
      throw error;
    }
  }

  /**
   * Get connection logs
   */
  async getConnectionLogs(filters = {}) {
    try {
      await this.ensureAuthenticated();

      let logs = [];

      if (this.config.deviceType === 'ftd') {
        // FTD logs through FMC
        const response = await this.makeAuthenticatedRequest('GET', '/api/fmc_config/v1/domain/default/health/events');
        logs = response.data.items || [];
      } else {
        // ASA logs
        const response = await this.makeAuthenticatedRequest('GET', '/api/monitoring/logs/connection');
        logs = response.data.items || [];
      }

      logger.info('Retrieved connection logs', {
        count: logs.length,
        deviceType: this.config.deviceType,
      });

      return logs;
    } catch (error) {
      logger.error('Error retrieving connection logs:', error);
      throw error;
    }
  }

  /**
   * Get interface statistics
   */
  async getInterfaceStats() {
    try {
      await this.ensureAuthenticated();

      const response = await this.makeAuthenticatedRequest('GET', '/api/monitoring/interfaces');
      const interfaces = response.data.items || [];

      return interfaces.map(iface => ({
        name: iface.name,
        status: iface.status,
        ipAddress: iface.ipAddress,
        speed: iface.speed,
        bytesIn: iface.bytesIn,
        bytesOut: iface.bytesOut,
        packetsIn: iface.packetsIn,
        packetsOut: iface.packetsOut,
      }));
    } catch (error) {
      logger.error('Error getting interface stats:', error);
      throw error;
    }
  }

  /**
   * Test connection to the firewall
   */
  async testConnection() {
    try {
      await this.authenticate();
      const systemInfo = await this.getSystemInfo();
      
      logger.info('Successfully connected to Cisco ASA/FTD', {
        hostname: systemInfo.hostname,
        model: systemInfo.model,
        version: systemInfo.version,
        deviceType: this.config.deviceType,
      });

      return {
        success: true,
        systemInfo,
        deviceType: this.config.deviceType,
        connectedAt: new Date(),
      };
    } catch (error) {
      logger.error('Failed to connect to Cisco ASA/FTD:', error);
      return {
        success: false,
        error: error.message,
        deviceType: this.config.deviceType,
        testedAt: new Date(),
      };
    }
  }

  /**
   * Apply configuration (save config)
   */
  async applyConfiguration() {
    try {
      if (this.config.deviceType === 'ftd') {
        // FTD deployments are handled through FMC
        await this.deployFTDChanges();
      } else {
        // ASA write memory
        await this.saveASAConfig();
      }

      logger.info('Configuration applied successfully');
      return { success: true, timestamp: new Date() };
    } catch (error) {
      logger.error('Error applying configuration:', error);
      throw error;
    }
  }

  async saveASAConfig() {
    // Use SSH for write memory command
    await this.executeSSHCommand('write memory');
  }

  async deployFTDChanges() {
    // Deploy pending changes to FTD devices
    const response = await this.makeAuthenticatedRequest('POST', '/api/fmc_config/v1/domain/default/deployment/deploymentrequests', {
      type: 'DeploymentRequest',
      forceDeploy: false,
      ignoreWarning: true,
    });

    const deploymentId = response.data.id;
    
    // Monitor deployment status
    return this.waitForDeployment(deploymentId);
  }

  async waitForDeployment(deploymentId, maxWait = 300000) { // 5 minutes
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWait) {
      const response = await this.makeAuthenticatedRequest('GET', `/api/fmc_config/v1/domain/default/deployment/deploymentrequests/${deploymentId}`);
      const status = response.data.deploymentStatus;

      if (status === 'DEPLOYED') {
        return true;
      } else if (status === 'FAILED') {
        throw new Error('Deployment failed');
      }

      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
    }

    throw new Error('Deployment timeout');
  }
}

module.exports = CiscoASAIntegration;