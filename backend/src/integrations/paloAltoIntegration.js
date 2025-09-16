/**
 * Palo Alto Networks Firewall Integration
 * Provides integration with Palo Alto PAN-OS firewalls via XML API
 */

const axios = require('axios');
const xml2js = require('xml2js');
const crypto = require('crypto');
const logger = require('../config/logger');

class PaloAltoIntegration {
  constructor(config) {
    this.config = {
      hostname: config.hostname,
      username: config.username,
      password: config.password,
      apiKey: config.apiKey,
      port: config.port || 443,
      timeout: config.timeout || 30000,
      vsys: config.vsys || 'vsys1',
      deviceGroup: config.deviceGroup,
    };
    
    this.apiKey = null;
    this.sessionTimeout = null;
    this.rateLimiter = this.initializeRateLimiter();
  }

  /**
   * Initialize rate limiter for API calls
   */
  initializeRateLimiter() {
    return {
      calls: [],
      maxCalls: 100, // API calls per minute
      windowMs: 60000, // 1 minute
    };
  }

  /**
   * Authenticate with the Palo Alto firewall
   */
  async authenticate() {
    try {
      if (this.config.apiKey) {
        this.apiKey = this.config.apiKey;
        return true;
      }

      const response = await this.makeRequest('GET', '/api/', {
        type: 'keygen',
        user: this.config.username,
        password: this.config.password,
      });

      const result = await this.parseXMLResponse(response.data);
      
      if (result.response.$.status === 'success') {
        this.apiKey = result.response.result[0].key[0];
        this.sessionTimeout = Date.now() + (8 * 60 * 60 * 1000); // 8 hours
        
        logger.info('Successfully authenticated with Palo Alto firewall', {
          hostname: this.config.hostname,
        });
        
        return true;
      } else {
        throw new Error('Authentication failed: ' + result.response.msg[0]);
      }
    } catch (error) {
      logger.error('Error authenticating with Palo Alto firewall:', error);
      throw error;
    }
  }

  /**
   * Block an IP address on the firewall
   */
  async blockIP(ipAddress, reason = 'AutoSec Security Block') {
    try {
      await this.ensureAuthenticated();

      const addressName = `AutoSec_Block_${ipAddress.replace(/\./g, '_')}`;
      
      // Create address object
      await this.createAddressObject(addressName, ipAddress, reason);
      
      // Add to security rule or address group
      await this.addToBlockList(addressName);
      
      // Commit changes
      await this.commitChanges();

      logger.info('Successfully blocked IP address', {
        ipAddress,
        addressName,
        reason,
      });

      return {
        success: true,
        ipAddress,
        addressName,
        action: 'blocked',
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error blocking IP address:', error);
      throw error;
    }
  }

  /**
   * Unblock an IP address
   */
  async unblockIP(ipAddress) {
    try {
      await this.ensureAuthenticated();

      const addressName = `AutoSec_Block_${ipAddress.replace(/\./g, '_')}`;
      
      // Remove from block list
      await this.removeFromBlockList(addressName);
      
      // Delete address object
      await this.deleteAddressObject(addressName);
      
      // Commit changes
      await this.commitChanges();

      logger.info('Successfully unblocked IP address', {
        ipAddress,
        addressName,
      });

      return {
        success: true,
        ipAddress,
        addressName,
        action: 'unblocked',
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error unblocking IP address:', error);
      throw error;
    }
  }

  /**
   * Create a security rule
   */
  async createSecurityRule(ruleConfig) {
    try {
      await this.ensureAuthenticated();

      const {
        name,
        from = 'any',
        to = 'any',
        source = 'any',
        destination = 'any',
        sourceUser = 'any',
        category = 'any',
        application = 'any',
        service = 'any',
        action = 'deny',
        description = 'Created by AutoSec',
      } = ruleConfig;

      const xpath = this.buildXPath('security', 'rules', `entry[@name='${name}']`);
      
      const element = `
        <from>${this.formatListElement(from)}</from>
        <to>${this.formatListElement(to)}</to>
        <source>${this.formatListElement(source)}</source>
        <destination>${this.formatListElement(destination)}</destination>
        <source-user>${this.formatListElement(sourceUser)}</source-user>
        <category>${this.formatListElement(category)}</category>
        <application>${this.formatListElement(application)}</application>
        <service>${this.formatListElement(service)}</service>
        <action>${action}</action>
        <description>${description}</description>
      `;

      await this.makeAPIRequest('POST', {
        type: 'config',
        action: 'set',
        xpath,
        element,
      });

      logger.info('Successfully created security rule', { name, action });

      return {
        success: true,
        ruleName: name,
        action: 'created',
        timestamp: new Date(),
      };
    } catch (error) {
      logger.error('Error creating security rule:', error);
      throw error;
    }
  }

  /**
   * Get threat logs
   */
  async getThreatLogs(filters = {}) {
    try {
      await this.ensureAuthenticated();

      const {
        startTime = new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
        endTime = new Date(),
        maxLogs = 1000,
        logType = 'threat',
      } = filters;

      const query = this.buildLogQuery(filters, startTime, endTime);

      const response = await this.makeAPIRequest('GET', {
        type: 'log',
        'log-type': logType,
        query,
        nlogs: maxLogs,
      });

      const logs = await this.parseLogResponse(response);

      logger.info('Retrieved threat logs', {
        count: logs.length,
        startTime,
        endTime,
      });

      return logs;
    } catch (error) {
      logger.error('Error retrieving threat logs:', error);
      throw error;
    }
  }

  /**
   * Get traffic logs
   */
  async getTrafficLogs(filters = {}) {
    try {
      await this.ensureAuthenticated();

      const {
        startTime = new Date(Date.now() - 60 * 60 * 1000), // Last hour
        endTime = new Date(),
        maxLogs = 1000,
      } = filters;

      const query = this.buildLogQuery(filters, startTime, endTime);

      const response = await this.makeAPIRequest('GET', {
        type: 'log',
        'log-type': 'traffic',
        query,
        nlogs: maxLogs,
      });

      const logs = await this.parseLogResponse(response);

      logger.info('Retrieved traffic logs', {
        count: logs.length,
        startTime,
        endTime,
      });

      return logs;
    } catch (error) {
      logger.error('Error retrieving traffic logs:', error);
      throw error;
    }
  }

  /**
   * Get system information
   */
  async getSystemInfo() {
    try {
      await this.ensureAuthenticated();

      const response = await this.makeAPIRequest('GET', {
        type: 'op',
        cmd: '<show><system><info></info></system></show>',
      });

      const result = await this.parseXMLResponse(response.data);
      const systemInfo = result.response.result[0].system[0];

      return {
        hostname: systemInfo.hostname[0],
        ipAddress: systemInfo['ip-address'][0],
        model: systemInfo.model[0],
        serial: systemInfo.serial[0],
        swVersion: systemInfo['sw-version'][0],
        uptime: systemInfo.uptime[0],
        devicename: systemInfo.devicename[0],
      };
    } catch (error) {
      logger.error('Error getting system info:', error);
      throw error;
    }
  }

  /**
   * Monitor interface statistics
   */
  async getInterfaceStats() {
    try {
      await this.ensureAuthenticated();

      const response = await this.makeAPIRequest('GET', {
        type: 'op',
        cmd: '<show><interface>all</interface></show>',
      });

      const result = await this.parseXMLResponse(response.data);
      const interfaces = result.response.result[0].ifnet[0].entry || [];

      return interfaces.map(iface => ({
        name: iface.$.name,
        state: iface.state[0],
        ip: iface.ip ? iface.ip[0] : null,
        zone: iface.zone ? iface.zone[0] : null,
        mac: iface.mac ? iface.mac[0] : null,
        speed: iface.speed ? iface.speed[0] : null,
        duplex: iface.duplex ? iface.duplex[0] : null,
      }));
    } catch (error) {
      logger.error('Error getting interface stats:', error);
      throw error;
    }
  }

  /**
   * Helper methods
   */
  async ensureAuthenticated() {
    if (!this.apiKey || (this.sessionTimeout && Date.now() > this.sessionTimeout)) {
      await this.authenticate();
    }
  }

  async createAddressObject(name, ipAddress, description) {
    const xpath = this.buildXPath('address', `entry[@name='${name}']`);
    const element = `
      <ip-netmask>${ipAddress}</ip-netmask>
      <description>${description}</description>
    `;

    await this.makeAPIRequest('POST', {
      type: 'config',
      action: 'set',
      xpath,
      element,
    });
  }

  async deleteAddressObject(name) {
    const xpath = this.buildXPath('address', `entry[@name='${name}']`);
    
    await this.makeAPIRequest('DELETE', {
      type: 'config',
      action: 'delete',
      xpath,
    });
  }

  async addToBlockList(addressName) {
    // Add to existing security rule or create address group
    const groupName = 'AutoSec_Blocked_IPs';
    const xpath = this.buildXPath('address-group', `entry[@name='${groupName}']`, 'static', `member[text()='${addressName}']`);
    
    await this.makeAPIRequest('POST', {
      type: 'config',
      action: 'set',
      xpath,
      element: `<member>${addressName}</member>`,
    });
  }

  async removeFromBlockList(addressName) {
    const groupName = 'AutoSec_Blocked_IPs';
    const xpath = this.buildXPath('address-group', `entry[@name='${groupName}']`, 'static', `member[text()='${addressName}']`);
    
    await this.makeAPIRequest('DELETE', {
      type: 'config',
      action: 'delete',
      xpath,
    });
  }

  async commitChanges() {
    const response = await this.makeAPIRequest('POST', {
      type: 'commit',
      cmd: '<commit></commit>',
    });

    // Wait for commit to complete
    const result = await this.parseXMLResponse(response.data);
    const jobId = result.response.result[0].job[0];

    return this.waitForJob(jobId);
  }

  async waitForJob(jobId, maxWait = 60000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWait) {
      const response = await this.makeAPIRequest('GET', {
        type: 'op',
        cmd: `<show><jobs><id>${jobId}</id></jobs></show>`,
      });

      const result = await this.parseXMLResponse(response.data);
      const job = result.response.result[0].job[0];
      const status = job.status[0];

      if (status === 'FIN') {
        const result = job.result[0];
        if (result === 'OK') {
          return true;
        } else {
          throw new Error(`Job failed: ${result}`);
        }
      }

      await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
    }

    throw new Error('Job timeout');
  }

  buildXPath(...parts) {
    const vsysPath = this.config.deviceGroup ? 
      `/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='${this.config.deviceGroup}']` :
      `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='${this.config.vsys}']`;
    
    return vsysPath + '/' + parts.join('/');
  }

  formatListElement(value) {
    if (Array.isArray(value)) {
      return value.map(v => `<member>${v}</member>`).join('');
    }
    return `<member>${value}</member>`;
  }

  buildLogQuery(filters, startTime, endTime) {
    const conditions = [];
    
    // Time range
    conditions.push(`(receive_time geq '${startTime.toISOString()}')`);
    conditions.push(`(receive_time leq '${endTime.toISOString()}')`);
    
    // Additional filters
    if (filters.sourceIP) {
      conditions.push(`(src eq '${filters.sourceIP}')`);
    }
    if (filters.destinationIP) {
      conditions.push(`(dst eq '${filters.destinationIP}')`);
    }
    if (filters.action) {
      conditions.push(`(action eq '${filters.action}')`);
    }
    if (filters.severity) {
      conditions.push(`(severity eq '${filters.severity}')`);
    }

    return conditions.join(' and ');
  }

  async makeAPIRequest(method, params) {
    await this.checkRateLimit();

    params.key = this.apiKey;
    
    return this.makeRequest(method, '/api/', params);
  }

  async makeRequest(method, path, params) {
    const config = {
      method,
      url: `https://${this.config.hostname}:${this.config.port}${path}`,
      timeout: this.config.timeout,
      httpsAgent: new (require('https').Agent)({
        rejectUnauthorized: false, // Accept self-signed certificates
      }),
    };

    if (method === 'GET') {
      config.params = params;
    } else {
      config.data = params;
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

  async parseXMLResponse(xmlData) {
    const parser = new xml2js.Parser();
    return parser.parseStringPromise(xmlData);
  }

  async parseLogResponse(response) {
    const result = await this.parseXMLResponse(response.data);
    const logEntries = result.response.result[0].log[0].logs[0].entry || [];
    
    return logEntries.map(entry => {
      const log = {};
      Object.keys(entry).forEach(key => {
        if (key !== '$') {
          log[key] = entry[key][0];
        }
      });
      return log;
    });
  }

  async checkRateLimit() {
    const now = Date.now();
    
    // Remove old calls outside the window
    this.rateLimiter.calls = this.rateLimiter.calls.filter(
      timestamp => now - timestamp < this.rateLimiter.windowMs
    );

    // Check if we're at the limit
    if (this.rateLimiter.calls.length >= this.rateLimiter.maxCalls) {
      const oldestCall = Math.min(...this.rateLimiter.calls);
      const waitTime = this.rateLimiter.windowMs - (now - oldestCall);
      
      logger.warn(`Rate limit reached, waiting ${waitTime}ms`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    // Add current call
    this.rateLimiter.calls.push(now);
  }

  /**
   * Test connection to the firewall
   */
  async testConnection() {
    try {
      await this.authenticate();
      const systemInfo = await this.getSystemInfo();
      
      logger.info('Successfully connected to Palo Alto firewall', {
        hostname: systemInfo.hostname,
        model: systemInfo.model,
        version: systemInfo.swVersion,
      });

      return {
        success: true,
        systemInfo,
        connectedAt: new Date(),
      };
    } catch (error) {
      logger.error('Failed to connect to Palo Alto firewall:', error);
      return {
        success: false,
        error: error.message,
        testedAt: new Date(),
      };
    }
  }
}

module.exports = PaloAltoIntegration;