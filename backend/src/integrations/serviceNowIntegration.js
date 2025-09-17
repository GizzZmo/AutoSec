/**
 * ServiceNow Integration
 * Provides integration with ServiceNow for incident and ticket management
 */

const axios = require('axios');
const logger = require('../config/logger');

class ServiceNowIntegration {
  constructor(config) {
    this.config = config;
    this.baseUrl = config.instanceUrl;
    this.httpClient = this.createHttpClient();
  }

  /**
   * Create HTTP client with authentication
   */
  createHttpClient() {
    return axios.create({
      baseURL: `${this.baseUrl}/api/now`,
      timeout: 30000,
      auth: {
        username: this.config.username,
        password: this.config.password,
      },
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
      logger.info('Initializing ServiceNow integration...');
      
      // Test connectivity
      await this.healthCheck();
      
      logger.info('ServiceNow integration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize ServiceNow integration:', error);
      throw error;
    }
  }

  /**
   * Create ticket in ServiceNow
   */
  async createTicket(ticketData, options = {}) {
    try {
      const table = options.table || this.config.table;
      
      const recordData = {
        short_description: ticketData.title,
        description: ticketData.description,
        urgency: this.mapUrgency(ticketData.priority),
        impact: this.mapImpact(ticketData.severity),
        category: ticketData.category || 'Security',
        subcategory: ticketData.subcategory || 'Incident',
        caller_id: options.callerId,
        assigned_to: ticketData.assignee,
        assignment_group: options.assignmentGroup || this.config.assignmentGroup,
        // Custom fields for AutoSec metadata
        u_source: 'AutoSec',
        u_incident_id: ticketData.metadata?.incidentId,
        u_risk_score: ticketData.metadata?.riskScore,
        u_event_id: ticketData.metadata?.eventId,
      };

      // Remove undefined fields
      Object.keys(recordData).forEach(key => {
        if (recordData[key] === undefined) {
          delete recordData[key];
        }
      });

      const response = await this.httpClient.post(`/table/${table}`, recordData);
      const record = response.data.result;

      logger.info(`ServiceNow ticket created: ${record.number}`);
      return {
        success: true,
        ticketId: record.number,
        externalId: record.sys_id,
        ticketUrl: `${this.baseUrl}/${table}.do?sys_id=${record.sys_id}`,
        response: response.status,
      };
    } catch (error) {
      logger.error('Failed to create ServiceNow ticket:', error);
      throw error;
    }
  }

  /**
   * Update ticket in ServiceNow
   */
  async updateTicket(ticketId, updateData, options = {}) {
    try {
      const table = options.table || this.config.table;
      const updateFields = {};

      if (updateData.title) {
        updateFields.short_description = updateData.title;
      }

      if (updateData.description) {
        updateFields.description = updateData.description;
      }

      if (updateData.status) {
        updateFields.state = this.mapState(updateData.status);
      }

      if (updateData.priority) {
        updateFields.urgency = this.mapUrgency(updateData.priority);
      }

      if (updateData.assignee) {
        updateFields.assigned_to = updateData.assignee;
      }

      if (updateData.resolution) {
        updateFields.close_code = updateData.resolution;
        updateFields.close_notes = updateData.resolutionNotes;
      }

      // Handle custom fields
      if (updateData.syncedAt) {
        updateFields.u_last_synced = updateData.syncedAt.toISOString();
      }

      if (Object.keys(updateFields).length > 0) {
        const response = await this.httpClient.put(`/table/${table}/${ticketId}`, updateFields);
        
        logger.info(`ServiceNow ticket ${ticketId} updated successfully`);
        return {
          success: true,
          ticketId: response.data.result.number,
          sysId: response.data.result.sys_id,
          updated: true,
        };
      }

      return {
        success: true,
        ticketId,
        updated: false,
        reason: 'No fields to update',
      };
    } catch (error) {
      logger.error(`Failed to update ServiceNow ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Get ticket status
   */
  async getTicketStatus(ticketId) {
    try {
      const table = this.config.table;
      const response = await this.httpClient.get(`/table/${table}/${ticketId}`, {
        params: {
          sysparm_fields: 'number,state,assigned_to,urgency,impact,sys_updated_on,close_code',
        },
      });

      const record = response.data.result;
      
      return {
        success: true,
        ticketId: record.number,
        status: this.unmapState(record.state),
        assignee: record.assigned_to?.display_value,
        urgency: record.urgency,
        impact: record.impact,
        closeCode: record.close_code,
        lastUpdated: new Date(record.sys_updated_on),
      };
    } catch (error) {
      logger.error(`Failed to get ServiceNow ticket status ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Add comment to ticket
   */
  async addComment(ticketId, comment, options = {}) {
    try {
      const table = this.config.table;
      
      // ServiceNow uses work notes or comments field
      const updateData = options.internal ? 
        { work_notes: comment } : 
        { comments: comment };

      const response = await this.httpClient.put(`/table/${table}/${ticketId}`, updateData);
      
      logger.info(`Comment added to ServiceNow ticket ${ticketId}`);
      return {
        success: true,
        ticketId: response.data.result.number,
        commentType: options.internal ? 'work_notes' : 'comments',
      };
    } catch (error) {
      logger.error(`Failed to add comment to ServiceNow ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Close ticket
   */
  async closeTicket(ticketId, resolution, options = {}) {
    try {
      const table = this.config.table;
      
      const updateData = {
        state: this.mapState('closed'),
        close_code: resolution || 'Resolved',
        close_notes: options.comment || 'Ticket closed by AutoSec',
      };

      if (options.resolvedBy) {
        updateData.resolved_by = options.resolvedBy;
      }

      const response = await this.httpClient.put(`/table/${table}/${ticketId}`, updateData);

      logger.info(`ServiceNow ticket ${ticketId} closed with resolution: ${resolution}`);
      return {
        success: true,
        ticketId: response.data.result.number,
        resolution,
        state: updateData.state,
      };
    } catch (error) {
      logger.error(`Failed to close ServiceNow ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Assign ticket to user
   */
  async assignTicket(ticketId, assignee, options = {}) {
    try {
      const table = this.config.table;
      
      const updateData = {
        assigned_to: assignee,
      };

      if (options.assignmentGroup) {
        updateData.assignment_group = options.assignmentGroup;
      }

      if (options.comment) {
        updateData.work_notes = `Assigned to ${assignee}. ${options.comment}`;
      }

      const response = await this.httpClient.put(`/table/${table}/${ticketId}`, updateData);

      logger.info(`ServiceNow ticket ${ticketId} assigned to ${assignee}`);
      return {
        success: true,
        ticketId: response.data.result.number,
        assignee,
      };
    } catch (error) {
      logger.error(`Failed to assign ServiceNow ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Search tickets
   */
  async searchTickets(query, options = {}) {
    try {
      const table = options.table || this.config.table;
      const sysparmQuery = this.buildQuery(query, options);
      
      const response = await this.httpClient.get(`/table/${table}`, {
        params: {
          sysparm_query: sysparmQuery,
          sysparm_offset: options.offset || 0,
          sysparm_limit: options.limit || 50,
          sysparm_fields: options.fields || 'number,short_description,state,assigned_to,sys_created_on,sys_updated_on,urgency',
          sysparm_order_by: options.orderBy || 'sys_created_on',
          sysparm_order_direction: options.orderDirection || 'desc',
        },
      });

      return {
        success: true,
        total: response.headers['x-total-count'] || response.data.result.length,
        tickets: response.data.result.map(record => ({
          id: record.sys_id,
          number: record.number,
          title: record.short_description,
          status: this.unmapState(record.state),
          assignee: record.assigned_to?.display_value,
          created: new Date(record.sys_created_on),
          updated: new Date(record.sys_updated_on),
          urgency: record.urgency,
          url: `${this.baseUrl}/${table}.do?sys_id=${record.sys_id}`,
        })),
      };
    } catch (error) {
      logger.error('Failed to search ServiceNow tickets:', error);
      throw error;
    }
  }

  /**
   * Get ticket details
   */
  async getTicketDetails(ticketId) {
    try {
      const table = this.config.table;
      const response = await this.httpClient.get(`/table/${table}/${ticketId}`);
      const record = response.data.result;

      return {
        success: true,
        ticket: {
          id: record.sys_id,
          number: record.number,
          title: record.short_description,
          description: record.description,
          status: this.unmapState(record.state),
          assignee: record.assigned_to?.display_value,
          caller: record.caller_id?.display_value,
          category: record.category,
          subcategory: record.subcategory,
          urgency: record.urgency,
          impact: record.impact,
          priority: record.priority,
          assignmentGroup: record.assignment_group?.display_value,
          created: new Date(record.sys_created_on),
          updated: new Date(record.sys_updated_on),
          closeCode: record.close_code,
          closeNotes: record.close_notes,
          workNotes: record.work_notes,
          comments: record.comments,
          url: `${this.baseUrl}/${table}.do?sys_id=${record.sys_id}`,
          // AutoSec specific fields
          source: record.u_source,
          incidentId: record.u_incident_id,
          riskScore: record.u_risk_score,
          eventId: record.u_event_id,
        },
      };
    } catch (error) {
      logger.error(`Failed to get ServiceNow ticket details ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Build ServiceNow query string
   */
  buildQuery(query, options) {
    const queryParts = [];

    // Text search
    if (query.text) {
      queryParts.push(`short_descriptionLIKE${query.text}^ORdescriptionLIKE${query.text}`);
    }

    // Status filter
    if (query.status) {
      const statuses = Array.isArray(query.status) ? query.status : [query.status];
      const stateValues = statuses.map(s => this.mapState(s));
      queryParts.push(`stateIN${stateValues.join(',')}`);
    }

    // Assignee filter
    if (query.assignee) {
      queryParts.push(`assigned_to.user_name=${query.assignee}`);
    }

    // Priority/Urgency filter
    if (query.priority) {
      queryParts.push(`urgency=${this.mapUrgency(query.priority)}`);
    }

    // Date range filter
    if (query.createdAfter) {
      queryParts.push(`sys_created_on>=${new Date(query.createdAfter).toISOString()}`);
    }

    if (query.createdBefore) {
      queryParts.push(`sys_created_on<=${new Date(query.createdBefore).toISOString()}`);
    }

    // Category filter
    if (query.category) {
      queryParts.push(`category=${query.category}`);
    }

    // AutoSec specific filters
    if (query.incidentId) {
      queryParts.push(`u_incident_id=${query.incidentId}`);
    }

    if (query.source) {
      queryParts.push(`u_source=${query.source}`);
    }

    return queryParts.length > 0 ? queryParts.join('^') : '';
  }

  /**
   * Map priority to ServiceNow urgency
   */
  mapUrgency(priority) {
    const urgencyMap = {
      'highest': '1',
      'high': '2',
      'medium': '3',
      'low': '4',
      'lowest': '5',
      'critical': '1',
      'p1': '1',
      'p2': '2',
      'p3': '3',
      'p4': '4',
      'p5': '5',
    };
    return urgencyMap[priority?.toLowerCase()] || '3';
  }

  /**
   * Map severity to ServiceNow impact
   */
  mapImpact(severity) {
    const impactMap = {
      'critical': '1',
      'high': '2',
      'medium': '3',
      'low': '4',
      'info': '5',
    };
    return impactMap[severity?.toLowerCase()] || '3';
  }

  /**
   * Map status to ServiceNow state
   */
  mapState(status) {
    const stateMap = {
      'new': '1',
      'open': '2',
      'in_progress': '2',
      'investigating': '2',
      'on_hold': '3',
      'resolved': '6',
      'closed': '7',
      'cancelled': '8',
    };
    return stateMap[status?.toLowerCase()] || '1';
  }

  /**
   * Unmap ServiceNow state to standard status
   */
  unmapState(state) {
    const stateMap = {
      '1': 'new',
      '2': 'in_progress',
      '3': 'on_hold',
      '4': 'awaiting_problem',
      '5': 'awaiting_vendor',
      '6': 'resolved',
      '7': 'closed',
      '8': 'cancelled',
    };
    return stateMap[state?.toString()] || 'unknown';
  }

  /**
   * Perform health check
   */
  async healthCheck() {
    try {
      const response = await this.httpClient.get('/table/sys_user?sysparm_limit=1');
      return response.status === 200;
    } catch (error) {
      logger.error('ServiceNow health check failed:', error);
      return false;
    }
  }

  /**
   * Get integration info
   */
  getInfo() {
    return {
      type: 'servicenow',
      baseUrl: this.baseUrl,
      table: this.config.table,
      assignmentGroup: this.config.assignmentGroup,
      status: 'connected',
    };
  }
}

module.exports = ServiceNowIntegration;