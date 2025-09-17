/**
 * OpenDaylight SDN Controller Integration
 * Provides integration with OpenDaylight SDN controller
 */

const axios = require('axios');
const logger = require('../config/logger');

class OpenDaylightIntegration {
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
      logger.info('Initializing OpenDaylight integration...');
      
      // Test connectivity
      await this.healthCheck();
      
      logger.info('OpenDaylight integration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize OpenDaylight integration:', error);
      throw error;
    }
  }

  /**
   * Block an IP address by creating a drop flow rule
   */
  async blockIP(ipAddress, options = {}) {
    try {
      const flowRule = {
        'flow-node-inventory:flow': [
          {
            id: `autosec-block-${ipAddress}-${Date.now()}`,
            'flow-name': `AutoSec Block ${ipAddress}`,
            'table_id': options.tableId || 0,
            priority: options.priority || 1000,
            'hard-timeout': options.hardTimeout || 0,
            'idle-timeout': options.idleTimeout || 0,
            match: {
              'ethernet-match': {
                'ethernet-type': {
                  type: 2048 // IPv4
                }
              },
              'ipv4-source': ipAddress
            },
            instructions: {
              instruction: [
                {
                  order: 0,
                  'apply-actions': {
                    action: [] // Empty actions = drop
                  }
                }
              ]
            }
          }
        ]
      };

      // Get all nodes (switches) in the topology
      const nodes = await this.getNodes();
      const results = [];

      for (const node of nodes) {
        try {
          const response = await this.httpClient.put(
            `/restconf/config/opendaylight-inventory:nodes/node/${node.id}/table/0/flow/${flowRule['flow-node-inventory:flow'][0].id}`,
            flowRule
          );
          
          results.push({
            nodeId: node.id,
            success: true,
            flowId: flowRule['flow-node-inventory:flow'][0].id,
            response: response.status
          });
        } catch (error) {
          logger.error(`Failed to install flow rule on node ${node.id}:`, error);
          results.push({
            nodeId: node.id,
            success: false,
            error: error.message
          });
        }
      }

      logger.info(`Blocked IP ${ipAddress} on OpenDaylight controller`);
      return { success: true, results };
    } catch (error) {
      logger.error(`Failed to block IP ${ipAddress} on OpenDaylight:`, error);
      throw error;
    }
  }

  /**
   * Unblock an IP address by removing flow rules
   */
  async unblockIP(ipAddress, options = {}) {
    try {
      // Find and remove all flow rules blocking this IP
      const nodes = await this.getNodes();
      const results = [];

      for (const node of nodes) {
        try {
          const flows = await this.getFlowsForNode(node.id);
          const blockingFlows = flows.filter(flow => 
            flow['flow-name'] && flow['flow-name'].includes(`AutoSec Block ${ipAddress}`)
          );

          for (const flow of blockingFlows) {
            await this.httpClient.delete(
              `/restconf/config/opendaylight-inventory:nodes/node/${node.id}/table/${flow.table_id}/flow/${flow.id}`
            );
            
            results.push({
              nodeId: node.id,
              flowId: flow.id,
              success: true
            });
          }
        } catch (error) {
          logger.error(`Failed to remove flow rules from node ${node.id}:`, error);
          results.push({
            nodeId: node.id,
            success: false,
            error: error.message
          });
        }
      }

      logger.info(`Unblocked IP ${ipAddress} on OpenDaylight controller`);
      return { success: true, results };
    } catch (error) {
      logger.error(`Failed to unblock IP ${ipAddress} on OpenDaylight:`, error);
      throw error;
    }
  }

  /**
   * Create a custom flow rule
   */
  async createFlowRule(ruleConfig) {
    try {
      const flowRule = this.buildFlowRule(ruleConfig);
      const nodeId = ruleConfig.nodeId || 'openflow:1'; // Default node
      
      const response = await this.httpClient.put(
        `/restconf/config/opendaylight-inventory:nodes/node/${nodeId}/table/${ruleConfig.tableId || 0}/flow/${flowRule.id}`,
        { 'flow-node-inventory:flow': [flowRule] }
      );

      logger.info(`Created flow rule ${flowRule.id} on OpenDaylight controller`);
      return {
        success: true,
        flowId: flowRule.id,
        nodeId,
        response: response.status
      };
    } catch (error) {
      logger.error('Failed to create flow rule on OpenDaylight:', error);
      throw error;
    }
  }

  /**
   * Get network topology
   */
  async getTopology() {
    try {
      const response = await this.httpClient.get('/restconf/operational/network-topology:network-topology/');
      
      return {
        topology: response.data,
        timestamp: Date.now(),
        controller: 'opendaylight'
      };
    } catch (error) {
      logger.error('Failed to get topology from OpenDaylight:', error);
      throw error;
    }
  }

  /**
   * Get flow statistics
   */
  async getFlowStatistics(filters = {}) {
    try {
      const nodes = await this.getNodes();
      const statistics = {};

      for (const node of nodes) {
        try {
          const response = await this.httpClient.get(
            `/restconf/operational/opendaylight-inventory:nodes/node/${node.id}/table/0`
          );
          
          statistics[node.id] = {
            flows: response.data['flow-node-inventory:table']?.[0]?.['flow-node-inventory:flow'] || [],
            timestamp: Date.now()
          };
        } catch (error) {
          logger.error(`Failed to get statistics for node ${node.id}:`, error);
          statistics[node.id] = { error: error.message };
        }
      }

      return statistics;
    } catch (error) {
      logger.error('Failed to get flow statistics from OpenDaylight:', error);
      throw error;
    }
  }

  /**
   * Get all nodes in the network
   */
  async getNodes() {
    try {
      const response = await this.httpClient.get('/restconf/operational/opendaylight-inventory:nodes/');
      const nodes = response.data['opendaylight-inventory:nodes']?.node || [];
      
      return nodes.map(node => ({
        id: node.id,
        connectorInventory: node['node-connector'] || []
      }));
    } catch (error) {
      logger.error('Failed to get nodes from OpenDaylight:', error);
      return [];
    }
  }

  /**
   * Get flows for a specific node
   */
  async getFlowsForNode(nodeId) {
    try {
      const response = await this.httpClient.get(
        `/restconf/operational/opendaylight-inventory:nodes/node/${nodeId}/table/0`
      );
      
      return response.data['flow-node-inventory:table']?.[0]?.['flow-node-inventory:flow'] || [];
    } catch (error) {
      logger.error(`Failed to get flows for node ${nodeId}:`, error);
      return [];
    }
  }

  /**
   * Build a flow rule from configuration
   */
  buildFlowRule(config) {
    return {
      id: config.id || `autosec-${Date.now()}`,
      'flow-name': config.name || 'AutoSec Flow Rule',
      'table_id': config.tableId || 0,
      priority: config.priority || 1000,
      'hard-timeout': config.hardTimeout || 0,
      'idle-timeout': config.idleTimeout || 0,
      match: config.match || {},
      instructions: config.instructions || {
        instruction: [
          {
            order: 0,
            'apply-actions': {
              action: config.actions || []
            }
          }
        ]
      }
    };
  }

  /**
   * Perform health check
   */
  async healthCheck() {
    try {
      const response = await this.httpClient.get('/restconf/operational/opendaylight-inventory:nodes/');
      return response.status === 200;
    } catch (error) {
      logger.error('OpenDaylight health check failed:', error);
      return false;
    }
  }

  /**
   * Get integration info
   */
  getInfo() {
    return {
      type: 'opendaylight',
      baseUrl: this.baseUrl,
      status: 'connected'
    };
  }
}

module.exports = OpenDaylightIntegration;