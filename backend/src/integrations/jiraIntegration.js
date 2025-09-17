/**
 * JIRA Integration
 * Provides integration with Atlassian JIRA for ticket management
 */

const axios = require('axios');
const logger = require('../config/logger');

class JiraIntegration {
  constructor(config) {
    this.config = config;
    this.baseUrl = config.url;
    this.httpClient = this.createHttpClient();
  }

  /**
   * Create HTTP client with authentication
   */
  createHttpClient() {
    const auth = this.config.apiToken ? 
      { username: this.config.username, password: this.config.apiToken } :
      { username: this.config.username, password: this.config.password };

    return axios.create({
      baseURL: `${this.baseUrl}/rest/api/2`,
      timeout: 30000,
      auth,
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
      logger.info('Initializing JIRA integration...');
      
      // Test connectivity
      await this.healthCheck();
      
      logger.info('JIRA integration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize JIRA integration:', error);
      throw error;
    }
  }

  /**
   * Create ticket in JIRA
   */
  async createTicket(ticketData, options = {}) {
    try {
      const issueData = {
        fields: {
          project: { key: options.projectKey || this.config.projectKey },
          summary: ticketData.title,
          description: ticketData.description,
          issuetype: { name: options.issueType || this.config.issueType },
          priority: { name: this.mapPriority(ticketData.priority) },
          reporter: options.reporter ? { name: options.reporter } : undefined,
          assignee: ticketData.assignee ? { name: ticketData.assignee } : undefined,
          labels: ticketData.labels || [],
          duedate: ticketData.dueDate ? new Date(ticketData.dueDate).toISOString().split('T')[0] : undefined,
          // Custom fields for AutoSec metadata
          ...(this.config.customFields && {
            [this.config.customFields.source]: 'AutoSec',
            [this.config.customFields.incidentId]: ticketData.metadata?.incidentId,
            [this.config.customFields.riskScore]: ticketData.metadata?.riskScore,
          }),
        },
      };

      // Remove undefined fields
      Object.keys(issueData.fields).forEach(key => {
        if (issueData.fields[key] === undefined) {
          delete issueData.fields[key];
        }
      });

      const response = await this.httpClient.post('/issue', issueData);
      const issue = response.data;

      logger.info(`JIRA ticket created: ${issue.key}`);
      return {
        success: true,
        ticketId: issue.key,
        externalId: issue.id,
        ticketUrl: `${this.baseUrl}/browse/${issue.key}`,
        response: response.status,
      };
    } catch (error) {
      logger.error('Failed to create JIRA ticket:', error);
      throw error;
    }
  }

  /**
   * Update ticket in JIRA
   */
  async updateTicket(ticketId, updateData, options = {}) {
    try {
      const updateFields = {};

      if (updateData.title) {
        updateFields.summary = [{ set: updateData.title }];
      }

      if (updateData.description) {
        updateFields.description = [{ set: updateData.description }];
      }

      if (updateData.status) {
        // Handle status transition
        const transitions = await this.getAvailableTransitions(ticketId);
        const targetTransition = transitions.find(t => 
          t.to.name.toLowerCase() === updateData.status.toLowerCase()
        );

        if (targetTransition) {
          await this.httpClient.post(`/issue/${ticketId}/transitions`, {
            transition: { id: targetTransition.id }
          });
        }
      }

      if (updateData.priority) {
        updateFields.priority = [{ set: { name: this.mapPriority(updateData.priority) } }];
      }

      if (updateData.assignee) {
        updateFields.assignee = [{ set: { name: updateData.assignee } }];
      }

      if (updateData.labels) {
        updateFields.labels = [{ set: updateData.labels }];
      }

      // Apply field updates if any
      if (Object.keys(updateFields).length > 0) {
        await this.httpClient.put(`/issue/${ticketId}`, {
          update: updateFields
        });
      }

      logger.info(`JIRA ticket ${ticketId} updated successfully`);
      return {
        success: true,
        ticketId,
        updated: Object.keys(updateFields).length > 0,
      };
    } catch (error) {
      logger.error(`Failed to update JIRA ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Get ticket status
   */
  async getTicketStatus(ticketId) {
    try {
      const response = await this.httpClient.get(`/issue/${ticketId}`, {
        params: {
          fields: 'status,updated,assignee,priority,resolution',
        },
      });

      const issue = response.data;
      
      return {
        success: true,
        ticketId,
        status: issue.fields.status.name,
        statusCategory: issue.fields.status.statusCategory.name,
        assignee: issue.fields.assignee?.displayName,
        priority: issue.fields.priority?.name,
        resolution: issue.fields.resolution?.name,
        lastUpdated: new Date(issue.fields.updated),
      };
    } catch (error) {
      logger.error(`Failed to get JIRA ticket status ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Add comment to ticket
   */
  async addComment(ticketId, comment, options = {}) {
    try {
      const commentData = {
        body: comment,
        author: options.author ? { name: options.author } : undefined,
        visibility: options.visibility ? {
          type: 'role',
          value: options.visibility,
        } : undefined,
      };

      // Remove undefined fields
      Object.keys(commentData).forEach(key => {
        if (commentData[key] === undefined) {
          delete commentData[key];
        }
      });

      const response = await this.httpClient.post(`/issue/${ticketId}/comment`, commentData);
      
      logger.info(`Comment added to JIRA ticket ${ticketId}`);
      return {
        success: true,
        commentId: response.data.id,
        ticketId,
      };
    } catch (error) {
      logger.error(`Failed to add comment to JIRA ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Close ticket
   */
  async closeTicket(ticketId, resolution, options = {}) {
    try {
      // Get available transitions
      const transitions = await this.getAvailableTransitions(ticketId);
      
      // Find close/done/resolved transition
      const closeTransition = transitions.find(t => 
        ['close', 'done', 'resolve', 'closed', 'resolved'].some(keyword =>
          t.name.toLowerCase().includes(keyword) || t.to.name.toLowerCase().includes(keyword)
        )
      );

      if (!closeTransition) {
        throw new Error('No close transition available for this ticket');
      }

      // Transition the ticket
      const transitionData = {
        transition: { id: closeTransition.id },
        fields: {},
      };

      // Set resolution if available
      if (resolution && closeTransition.fields?.resolution) {
        transitionData.fields.resolution = { name: resolution };
      }

      await this.httpClient.post(`/issue/${ticketId}/transitions`, transitionData);

      // Add closing comment if provided
      if (options.comment) {
        await this.addComment(ticketId, options.comment, options);
      }

      logger.info(`JIRA ticket ${ticketId} closed with resolution: ${resolution}`);
      return {
        success: true,
        ticketId,
        resolution,
        transitionUsed: closeTransition.name,
      };
    } catch (error) {
      logger.error(`Failed to close JIRA ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Assign ticket to user
   */
  async assignTicket(ticketId, assignee, options = {}) {
    try {
      await this.httpClient.put(`/issue/${ticketId}/assignee`, {
        name: assignee,
      });

      // Add assignment comment if provided
      if (options.comment) {
        await this.addComment(ticketId, `Assigned to ${assignee}. ${options.comment}`, options);
      }

      logger.info(`JIRA ticket ${ticketId} assigned to ${assignee}`);
      return {
        success: true,
        ticketId,
        assignee,
      };
    } catch (error) {
      logger.error(`Failed to assign JIRA ticket ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Search tickets
   */
  async searchTickets(query, options = {}) {
    try {
      const jqlQuery = this.buildJQLQuery(query, options);
      
      const response = await this.httpClient.post('/search', {
        jql: jqlQuery,
        startAt: options.startAt || 0,
        maxResults: options.maxResults || 50,
        fields: options.fields || ['summary', 'status', 'assignee', 'created', 'updated', 'priority'],
      });

      return {
        success: true,
        total: response.data.total,
        tickets: response.data.issues.map(issue => ({
          id: issue.id,
          key: issue.key,
          summary: issue.fields.summary,
          status: issue.fields.status.name,
          assignee: issue.fields.assignee?.displayName,
          created: new Date(issue.fields.created),
          updated: new Date(issue.fields.updated),
          priority: issue.fields.priority?.name,
          url: `${this.baseUrl}/browse/${issue.key}`,
        })),
      };
    } catch (error) {
      logger.error('Failed to search JIRA tickets:', error);
      throw error;
    }
  }

  /**
   * Get ticket details
   */
  async getTicketDetails(ticketId) {
    try {
      const response = await this.httpClient.get(`/issue/${ticketId}`);
      const issue = response.data;

      return {
        success: true,
        ticket: {
          id: issue.id,
          key: issue.key,
          summary: issue.fields.summary,
          description: issue.fields.description,
          status: issue.fields.status.name,
          statusCategory: issue.fields.status.statusCategory.name,
          assignee: issue.fields.assignee?.displayName,
          reporter: issue.fields.reporter?.displayName,
          priority: issue.fields.priority?.name,
          resolution: issue.fields.resolution?.name,
          created: new Date(issue.fields.created),
          updated: new Date(issue.fields.updated),
          dueDate: issue.fields.duedate ? new Date(issue.fields.duedate) : null,
          labels: issue.fields.labels || [],
          components: issue.fields.components?.map(c => c.name) || [],
          fixVersions: issue.fields.fixVersions?.map(v => v.name) || [],
          url: `${this.baseUrl}/browse/${issue.key}`,
        },
      };
    } catch (error) {
      logger.error(`Failed to get JIRA ticket details ${ticketId}:`, error);
      throw error;
    }
  }

  /**
   * Get available transitions for a ticket
   */
  async getAvailableTransitions(ticketId) {
    try {
      const response = await this.httpClient.get(`/issue/${ticketId}/transitions`);
      return response.data.transitions;
    } catch (error) {
      logger.error(`Failed to get transitions for JIRA ticket ${ticketId}:`, error);
      return [];
    }
  }

  /**
   * Build JQL query from search parameters
   */
  buildJQLQuery(query, options) {
    const jqlParts = [];

    // Project filter
    if (options.projectKey || this.config.projectKey) {
      jqlParts.push(`project = "${options.projectKey || this.config.projectKey}"`);
    }

    // Text search
    if (query.text) {
      jqlParts.push(`text ~ "${query.text}"`);
    }

    // Status filter
    if (query.status) {
      const statuses = Array.isArray(query.status) ? query.status : [query.status];
      jqlParts.push(`status IN (${statuses.map(s => `"${s}"`).join(', ')})`);
    }

    // Assignee filter
    if (query.assignee) {
      jqlParts.push(`assignee = "${query.assignee}"`);
    }

    // Priority filter
    if (query.priority) {
      jqlParts.push(`priority = "${this.mapPriority(query.priority)}"`);
    }

    // Date range filter
    if (query.createdAfter) {
      jqlParts.push(`created >= "${new Date(query.createdAfter).toISOString().split('T')[0]}"`);
    }

    if (query.createdBefore) {
      jqlParts.push(`created <= "${new Date(query.createdBefore).toISOString().split('T')[0]}"`);
    }

    // Labels filter
    if (query.labels) {
      const labels = Array.isArray(query.labels) ? query.labels : [query.labels];
      jqlParts.push(`labels IN (${labels.map(l => `"${l}"`).join(', ')})`);
    }

    // AutoSec specific filters
    if (query.incidentId) {
      jqlParts.push(`"AutoSec Incident ID" ~ "${query.incidentId}"`);
    }

    // Default sorting
    const orderBy = options.orderBy || 'created DESC';
    const jql = jqlParts.length > 0 ? jqlParts.join(' AND ') + ` ORDER BY ${orderBy}` : `ORDER BY ${orderBy}`;

    return jql;
  }

  /**
   * Map priority levels to JIRA priorities
   */
  mapPriority(priority) {
    const priorityMap = {
      'highest': 'Highest',
      'high': 'High',
      'medium': 'Medium',
      'low': 'Low',
      'lowest': 'Lowest',
      'critical': 'Highest',
      'p1': 'Highest',
      'p2': 'High',
      'p3': 'Medium',
      'p4': 'Low',
      'p5': 'Lowest',
    };
    return priorityMap[priority?.toLowerCase()] || 'Medium';
  }

  /**
   * Perform health check
   */
  async healthCheck() {
    try {
      const response = await this.httpClient.get('/serverInfo');
      return response.status === 200;
    } catch (error) {
      logger.error('JIRA health check failed:', error);
      return false;
    }
  }

  /**
   * Get integration info
   */
  getInfo() {
    return {
      type: 'jira',
      baseUrl: this.baseUrl,
      projectKey: this.config.projectKey,
      status: 'connected',
    };
  }
}

module.exports = JiraIntegration;