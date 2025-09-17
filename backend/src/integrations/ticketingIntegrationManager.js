/**
 * Ticketing Integration Manager
 * Manages integrations with ticketing systems like JIRA and ServiceNow
 */

const JiraIntegration = require('./jiraIntegration');
const ServiceNowIntegration = require('./serviceNowIntegration');
const logger = require('../config/logger');

class TicketingIntegrationManager {
  constructor() {
    this.integrations = new Map();
    this.config = this.loadConfiguration();
    this.healthStatus = new Map();
    this.lastHealthCheck = null;
    this.ticketMappings = new Map();
  }

  /**
   * Load ticketing system configurations from environment
   */
  loadConfiguration() {
    return {
      jira: {
        enabled: process.env.JIRA_ENABLED === 'true',
        url: process.env.JIRA_URL,
        username: process.env.JIRA_USERNAME,
        password: process.env.JIRA_PASSWORD,
        apiToken: process.env.JIRA_API_TOKEN,
        projectKey: process.env.JIRA_PROJECT_KEY,
        issueType: process.env.JIRA_ISSUE_TYPE || 'Task',
      },
      servicenow: {
        enabled: process.env.SERVICENOW_ENABLED === 'true',
        instanceUrl: process.env.SERVICENOW_INSTANCE_URL,
        username: process.env.SERVICENOW_USERNAME,
        password: process.env.SERVICENOW_PASSWORD,
        table: process.env.SERVICENOW_TABLE || 'incident',
        assignmentGroup: process.env.SERVICENOW_ASSIGNMENT_GROUP,
      },
    };
  }

  /**
   * Initialize all enabled ticketing integrations
   */
  async initialize() {
    try {
      logger.info('Initializing ticketing integrations...');

      // Initialize JIRA
      if (this.config.jira.enabled) {
        await this.initializeIntegration('jira', new JiraIntegration(this.config.jira));
      }

      // Initialize ServiceNow
      if (this.config.servicenow.enabled) {
        await this.initializeIntegration('servicenow', new ServiceNowIntegration(this.config.servicenow));
      }

      logger.info(`Ticketing integrations initialized: ${Array.from(this.integrations.keys()).join(', ')}`);
    } catch (error) {
      logger.error('Error initializing ticketing integrations:', error);
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
      logger.info(`Ticketing integration '${name}' initialized successfully`);
    } catch (error) {
      logger.error(`Failed to initialize ticketing integration '${name}':`, error);
      this.healthStatus.set(name, { status: 'error', error: error.message, lastCheck: Date.now() });
      throw error;
    }
  }

  /**
   * Create ticket in all configured systems
   */
  async createTicket(ticketData, options = {}) {
    const results = [];
    const errors = [];

    // Normalize ticket data
    const normalizedTicket = this.normalizeTicketData(ticketData);

    for (const [name, integration] of this.integrations) {
      try {
        logger.info(`Creating ticket in ${name}`);
        const result = await integration.createTicket(normalizedTicket, options);
        results.push({ integration: name, success: true, result });
        
        // Store ticket mapping for future updates
        this.ticketMappings.set(`${name}-${result.ticketId}`, {
          integration: name,
          ticketId: result.ticketId,
          externalId: result.externalId || result.ticketId,
          sourceData: ticketData,
          createdAt: new Date(),
        });
      } catch (error) {
        logger.error(`Failed to create ticket in ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Update ticket in all systems where it exists
   */
  async updateTicket(ticketReference, updateData, options = {}) {
    const results = [];
    const errors = [];

    // Find all tickets matching the reference
    const matchingTickets = this.findTicketsByReference(ticketReference);

    for (const ticket of matchingTickets) {
      try {
        const integration = this.integrations.get(ticket.integration);
        if (integration) {
          logger.info(`Updating ticket ${ticket.ticketId} in ${ticket.integration}`);
          const result = await integration.updateTicket(ticket.externalId, updateData, options);
          results.push({ integration: ticket.integration, success: true, result });
        }
      } catch (error) {
        logger.error(`Failed to update ticket ${ticket.ticketId} in ${ticket.integration}:`, error);
        errors.push({ integration: ticket.integration, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Get ticket status from all systems
   */
  async getTicketStatus(ticketReference) {
    const statuses = {};
    const errors = [];

    const matchingTickets = this.findTicketsByReference(ticketReference);

    for (const ticket of matchingTickets) {
      try {
        const integration = this.integrations.get(ticket.integration);
        if (integration) {
          logger.debug(`Getting ticket status from ${ticket.integration}`);
          const status = await integration.getTicketStatus(ticket.externalId);
          statuses[ticket.integration] = status;
        }
      } catch (error) {
        logger.error(`Failed to get ticket status from ${ticket.integration}:`, error);
        errors.push({ integration: ticket.integration, error: error.message });
      }
    }

    return { statuses, errors };
  }

  /**
   * Add comment to ticket in all systems
   */
  async addComment(ticketReference, comment, options = {}) {
    const results = [];
    const errors = [];

    const matchingTickets = this.findTicketsByReference(ticketReference);

    for (const ticket of matchingTickets) {
      try {
        const integration = this.integrations.get(ticket.integration);
        if (integration) {
          logger.info(`Adding comment to ticket ${ticket.ticketId} in ${ticket.integration}`);
          const result = await integration.addComment(ticket.externalId, comment, options);
          results.push({ integration: ticket.integration, success: true, result });
        }
      } catch (error) {
        logger.error(`Failed to add comment to ticket ${ticket.ticketId} in ${ticket.integration}:`, error);
        errors.push({ integration: ticket.integration, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Close ticket in all systems
   */
  async closeTicket(ticketReference, resolution, options = {}) {
    const results = [];
    const errors = [];

    const matchingTickets = this.findTicketsByReference(ticketReference);

    for (const ticket of matchingTickets) {
      try {
        const integration = this.integrations.get(ticket.integration);
        if (integration) {
          logger.info(`Closing ticket ${ticket.ticketId} in ${ticket.integration}`);
          const result = await integration.closeTicket(ticket.externalId, resolution, options);
          results.push({ integration: ticket.integration, success: true, result });
        }
      } catch (error) {
        logger.error(`Failed to close ticket ${ticket.ticketId} in ${ticket.integration}:`, error);
        errors.push({ integration: ticket.integration, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Assign ticket to user in all systems
   */
  async assignTicket(ticketReference, assignee, options = {}) {
    const results = [];
    const errors = [];

    const matchingTickets = this.findTicketsByReference(ticketReference);

    for (const ticket of matchingTickets) {
      try {
        const integration = this.integrations.get(ticket.integration);
        if (integration) {
          logger.info(`Assigning ticket ${ticket.ticketId} to ${assignee} in ${ticket.integration}`);
          const result = await integration.assignTicket(ticket.externalId, assignee, options);
          results.push({ integration: ticket.integration, success: true, result });
        }
      } catch (error) {
        logger.error(`Failed to assign ticket ${ticket.ticketId} in ${ticket.integration}:`, error);
        errors.push({ integration: ticket.integration, error: error.message });
      }
    }

    return { results, errors, success: errors.length === 0 };
  }

  /**
   * Search tickets across all systems
   */
  async searchTickets(query, options = {}) {
    const results = {};
    const errors = [];

    for (const [name, integration] of this.integrations) {
      try {
        logger.debug(`Searching tickets in ${name}`);
        const tickets = await integration.searchTickets(query, options);
        results[name] = tickets;
      } catch (error) {
        logger.error(`Failed to search tickets in ${name}:`, error);
        errors.push({ integration: name, error: error.message });
      }
    }

    return { results, errors };
  }

  /**
   * Get ticket details from all systems
   */
  async getTicketDetails(ticketReference) {
    const details = {};
    const errors = [];

    const matchingTickets = this.findTicketsByReference(ticketReference);

    for (const ticket of matchingTickets) {
      try {
        const integration = this.integrations.get(ticket.integration);
        if (integration) {
          logger.debug(`Getting ticket details from ${ticket.integration}`);
          const detail = await integration.getTicketDetails(ticket.externalId);
          details[ticket.integration] = detail;
        }
      } catch (error) {
        logger.error(`Failed to get ticket details from ${ticket.integration}:`, error);
        errors.push({ integration: ticket.integration, error: error.message });
      }
    }

    return { details, errors };
  }

  /**
   * Sync ticket status across systems
   */
  async syncTicketStatus(ticketReference) {
    const statuses = await this.getTicketStatus(ticketReference);
    const syncResults = [];

    // Find the most recent status update
    let latestStatus = null;
    let latestTimestamp = null;

    for (const [system, status] of Object.entries(statuses.statuses || {})) {
      if (status.lastUpdated && (!latestTimestamp || status.lastUpdated > latestTimestamp)) {
        latestStatus = status;
        latestTimestamp = status.lastUpdated;
      }
    }

    // Update all other systems to match the latest status
    if (latestStatus) {
      const matchingTickets = this.findTicketsByReference(ticketReference);
      
      for (const ticket of matchingTickets) {
        try {
          const integration = this.integrations.get(ticket.integration);
          if (integration) {
            const currentStatus = statuses.statuses[ticket.integration];
            if (currentStatus && currentStatus.status !== latestStatus.status) {
              const updateResult = await integration.updateTicket(ticket.externalId, {
                status: latestStatus.status,
                syncedAt: new Date(),
              });
              syncResults.push({
                integration: ticket.integration,
                success: true,
                updated: true,
                result: updateResult,
              });
            } else {
              syncResults.push({
                integration: ticket.integration,
                success: true,
                updated: false,
                reason: 'Already in sync',
              });
            }
          }
        } catch (error) {
          logger.error(`Failed to sync ticket status in ${ticket.integration}:`, error);
          syncResults.push({
            integration: ticket.integration,
            success: false,
            error: error.message,
          });
        }
      }
    }

    return { syncResults, latestStatus };
  }

  /**
   * Normalize ticket data for all systems
   */
  normalizeTicketData(ticketData) {
    return {
      title: ticketData.title || ticketData.summary || 'AutoSec Security Incident',
      description: ticketData.description || ticketData.details || '',
      severity: this.normalizeSeverity(ticketData.severity || ticketData.priority),
      priority: this.normalizePriority(ticketData.priority || ticketData.severity),
      category: ticketData.category || 'Security',
      subcategory: ticketData.subcategory || 'Incident',
      assignee: ticketData.assignee,
      reporter: ticketData.reporter || 'AutoSec',
      labels: ticketData.labels || ticketData.tags || [],
      dueDate: ticketData.dueDate,
      metadata: {
        source: 'AutoSec',
        incidentId: ticketData.incidentId,
        eventId: ticketData.eventId,
        riskScore: ticketData.riskScore,
        entities: ticketData.entities,
        ...ticketData.metadata,
      },
    };
  }

  /**
   * Normalize severity levels
   */
  normalizeSeverity(severity) {
    const severityMap = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'info': 'low',
      '1': 'critical',
      '2': 'high',
      '3': 'medium',
      '4': 'low',
      '5': 'low',
    };
    return severityMap[severity?.toString()?.toLowerCase()] || 'medium';
  }

  /**
   * Normalize priority levels
   */
  normalizePriority(priority) {
    const priorityMap = {
      'critical': 'highest',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'info': 'lowest',
      'p1': 'highest',
      'p2': 'high',
      'p3': 'medium',
      'p4': 'low',
      'p5': 'lowest',
    };
    return priorityMap[priority?.toString()?.toLowerCase()] || 'medium';
  }

  /**
   * Find tickets by reference (incident ID, event ID, etc.)
   */
  findTicketsByReference(reference) {
    const tickets = [];
    
    for (const [key, ticket] of this.ticketMappings) {
      if (ticket.sourceData.incidentId === reference ||
          ticket.sourceData.eventId === reference ||
          ticket.ticketId === reference ||
          ticket.externalId === reference) {
        tickets.push(ticket);
      }
    }

    return tickets;
  }

  /**
   * Perform health check on all integrations
   */
  async performHealthCheck() {
    logger.info('Performing ticketing integration health check...');
    this.lastHealthCheck = Date.now();

    for (const [name, integration] of this.integrations) {
      try {
        const isHealthy = await integration.healthCheck();
        this.healthStatus.set(name, {
          status: isHealthy ? 'healthy' : 'unhealthy',
          lastCheck: this.lastHealthCheck,
        });
      } catch (error) {
        logger.error(`Health check failed for ticketing integration '${name}':`, error);
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
      ticketMappings: this.ticketMappings.size,
    };
  }

  /**
   * Get integration capabilities
   */
  getCapabilities() {
    const capabilities = {};

    for (const [name, integration] of this.integrations) {
      capabilities[name] = {
        createTicket: typeof integration.createTicket === 'function',
        updateTicket: typeof integration.updateTicket === 'function',
        getTicketStatus: typeof integration.getTicketStatus === 'function',
        addComment: typeof integration.addComment === 'function',
        closeTicket: typeof integration.closeTicket === 'function',
        assignTicket: typeof integration.assignTicket === 'function',
        searchTickets: typeof integration.searchTickets === 'function',
        getTicketDetails: typeof integration.getTicketDetails === 'function',
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
      ticketMappings: this.ticketMappings.size,
    };
  }

  /**
   * Get ticket mappings
   */
  getTicketMappings() {
    return Array.from(this.ticketMappings.values());
  }

  /**
   * Clean up old ticket mappings
   */
  cleanupOldMappings(maxAge = 90 * 24 * 60 * 60 * 1000) { // 90 days
    const cutoff = Date.now() - maxAge;
    
    for (const [key, mapping] of this.ticketMappings) {
      if (mapping.createdAt.getTime() < cutoff) {
        this.ticketMappings.delete(key);
      }
    }
  }
}

module.exports = new TicketingIntegrationManager();