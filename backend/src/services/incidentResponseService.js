/**
 * Incident Response Automation Service
 * Manages automated response playbooks, workflows, and incident management
 */

const logger = require('../config/logger');
const ThreatEvent = require('../models/ThreatEvent');
const Incident = require('../models/Incident');
const Playbook = require('../models/Playbook');
const WorkflowEngine = require('./workflowEngine');
const TicketingIntegrationManager = require('../integrations/ticketingIntegrationManager');

class IncidentResponseService {
  constructor() {
    this.workflowEngine = new WorkflowEngine();
    this.activeIncidents = new Map();
    this.playbookLibrary = new Map();
    this.automationRules = new Map();
    this.responseHistory = [];
    this.config = this.loadConfiguration();
  }

  /**
   * Load incident response configurations
   */
  loadConfiguration() {
    return {
      autoEscalation: {
        enabled: process.env.IR_AUTO_ESCALATION === 'true',
        timeThresholds: {
          critical: parseInt(process.env.IR_CRITICAL_THRESHOLD) || 15, // minutes
          high: parseInt(process.env.IR_HIGH_THRESHOLD) || 60,
          medium: parseInt(process.env.IR_MEDIUM_THRESHOLD) || 240,
        },
      },
      autoAssignment: {
        enabled: process.env.IR_AUTO_ASSIGNMENT === 'true',
        rules: this.parseAssignmentRules(process.env.IR_ASSIGNMENT_RULES || ''),
      },
      notifications: {
        email: process.env.IR_EMAIL_NOTIFICATIONS === 'true',
        sms: process.env.IR_SMS_NOTIFICATIONS === 'true',
        slack: process.env.IR_SLACK_NOTIFICATIONS === 'true',
      },
      playbooks: {
        autoExecute: process.env.IR_AUTO_EXECUTE_PLAYBOOKS === 'true',
        approvalRequired: process.env.IR_APPROVAL_REQUIRED === 'true',
      },
    };
  }

  /**
   * Initialize incident response service
   */
  async initialize() {
    try {
      logger.info('Initializing Incident Response Service...');

      // Load playbooks from database
      await this.loadPlaybooks();

      // Initialize workflow engine
      await this.workflowEngine.initialize();

      // Initialize ticketing integrations
      await TicketingIntegrationManager.initialize();

      // Set up automated monitoring
      this.startAutomatedMonitoring();

      logger.info('Incident Response Service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Incident Response Service:', error);
      throw error;
    }
  }

  /**
   * Create incident from threat event
   */
  async createIncident(threatEvent, options = {}) {
    try {
      const incident = new Incident({
        incidentId: `INC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        title: threatEvent.title || `Security Incident: ${threatEvent.eventType}`,
        description: threatEvent.description,
        severity: threatEvent.severity,
        status: 'new',
        category: this.categorizeIncident(threatEvent),
        source: {
          eventId: threatEvent.eventId,
          system: threatEvent.source?.system,
          detector: threatEvent.source?.detector,
        },
        entities: threatEvent.entities,
        evidence: threatEvent.evidence,
        riskScore: threatEvent.riskScore,
        containmentStatus: 'not_started',
        createdBy: options.createdBy || 'system',
        timeline: [{
          timestamp: new Date(),
          action: 'incident_created',
          description: 'Incident created from threat event',
          userId: options.createdBy || 'system',
        }],
      });

      await incident.save();

      // Store in active incidents
      this.activeIncidents.set(incident.incidentId, incident);

      logger.info(`Incident ${incident.incidentId} created from threat event ${threatEvent.eventId}`);

      // Trigger automated response if enabled
      if (this.config.playbooks.autoExecute) {
        await this.triggerAutomatedResponse(incident);
      }

      // Auto-assign if enabled
      if (this.config.autoAssignment.enabled) {
        await this.autoAssignIncident(incident);
      }

      // Create ticket in external systems
      await this.createExternalTicket(incident);

      return incident;
    } catch (error) {
      logger.error('Failed to create incident:', error);
      throw error;
    }
  }

  /**
   * Execute incident response playbook
   */
  async executePlaybook(incidentId, playbookId, options = {}) {
    try {
      const incident = await this.getIncident(incidentId);
      const playbook = await this.getPlaybook(playbookId);

      if (!incident || !playbook) {
        throw new Error('Incident or playbook not found');
      }

      logger.info(`Executing playbook ${playbookId} for incident ${incidentId}`);

      // Create workflow execution context
      const executionContext = {
        incidentId: incidentId,
        playbookId: playbookId,
        incident: incident,
        playbook: playbook,
        executor: options.executor || 'system',
        startTime: new Date(),
        variables: { ...options.variables },
      };

      // Execute workflow
      const execution = await this.workflowEngine.executeWorkflow(
        playbook.workflow,
        executionContext
      );

      // Update incident with execution results
      await this.updateIncidentFromExecution(incident, execution);

      logger.info(`Playbook ${playbookId} execution completed for incident ${incidentId}`);
      return execution;
    } catch (error) {
      logger.error('Failed to execute playbook:', error);
      throw error;
    }
  }

  /**
   * Trigger automated response based on incident characteristics
   */
  async triggerAutomatedResponse(incident) {
    try {
      // Find matching playbooks based on incident characteristics
      const matchingPlaybooks = await this.findMatchingPlaybooks(incident);

      for (const playbook of matchingPlaybooks) {
        // Check if approval is required
        if (this.config.playbooks.approvalRequired && playbook.requiresApproval) {
          await this.requestApproval(incident, playbook);
        } else {
          // Execute playbook automatically
          await this.executePlaybook(incident.incidentId, playbook.playbookId, {
            executor: 'automation',
            automated: true,
          });
        }
      }
    } catch (error) {
      logger.error('Failed to trigger automated response:', error);
    }
  }

  /**
   * Find playbooks that match incident characteristics
   */
  async findMatchingPlaybooks(incident) {
    try {
      const playbooks = await Playbook.find({
        active: true,
        triggers: {
          $elemMatch: {
            type: 'incident',
            conditions: {
              $elemMatch: {
                field: { $in: ['severity', 'category', 'riskScore'] },
                operator: 'equals',
                value: { $in: [incident.severity, incident.category, incident.riskScore] }
              }
            }
          }
        }
      });

      return playbooks.filter(playbook => this.evaluatePlaybookConditions(playbook, incident));
    } catch (error) {
      logger.error('Failed to find matching playbooks:', error);
      return [];
    }
  }

  /**
   * Evaluate playbook conditions against incident
   */
  evaluatePlaybookConditions(playbook, incident) {
    try {
      for (const trigger of playbook.triggers) {
        if (trigger.type === 'incident') {
          let allConditionsMet = true;

          for (const condition of trigger.conditions) {
            const incidentValue = this.getIncidentFieldValue(incident, condition.field);
            const conditionMet = this.evaluateCondition(
              incidentValue,
              condition.operator,
              condition.value
            );

            if (!conditionMet) {
              allConditionsMet = false;
              break;
            }
          }

          if (allConditionsMet) {
            return true;
          }
        }
      }

      return false;
    } catch (error) {
      logger.error('Error evaluating playbook conditions:', error);
      return false;
    }
  }

  /**
   * Get field value from incident object
   */
  getIncidentFieldValue(incident, fieldPath) {
    const parts = fieldPath.split('.');
    let value = incident;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Evaluate condition
   */
  evaluateCondition(actualValue, operator, expectedValue) {
    switch (operator) {
      case 'equals':
        return actualValue === expectedValue;
      case 'not_equals':
        return actualValue !== expectedValue;
      case 'greater_than':
        return actualValue > expectedValue;
      case 'less_than':
        return actualValue < expectedValue;
      case 'greater_equal':
        return actualValue >= expectedValue;
      case 'less_equal':
        return actualValue <= expectedValue;
      case 'contains':
        return String(actualValue).includes(String(expectedValue));
      case 'starts_with':
        return String(actualValue).startsWith(String(expectedValue));
      case 'ends_with':
        return String(actualValue).endsWith(String(expectedValue));
      case 'regex':
        return new RegExp(expectedValue).test(String(actualValue));
      case 'in':
        return Array.isArray(expectedValue) && expectedValue.includes(actualValue);
      default:
        return false;
    }
  }

  /**
   * Auto-assign incident based on rules
   */
  async autoAssignIncident(incident) {
    try {
      const assignmentRules = this.config.autoAssignment.rules;

      for (const rule of assignmentRules) {
        if (this.evaluateAssignmentRule(rule, incident)) {
          await this.assignIncident(incident.incidentId, rule.assignee, {
            reason: 'Auto-assigned based on rule',
            ruleId: rule.id,
          });
          break;
        }
      }
    } catch (error) {
      logger.error('Failed to auto-assign incident:', error);
    }
  }

  /**
   * Assign incident to user or team
   */
  async assignIncident(incidentId, assignee, options = {}) {
    try {
      const incident = await Incident.findOne({ incidentId });

      if (!incident) {
        throw new Error('Incident not found');
      }

      incident.assignedTo = {
        assignee: assignee,
        assignedAt: new Date(),
        assignedBy: options.assignedBy || 'system',
        reason: options.reason,
      };

      incident.timeline.push({
        timestamp: new Date(),
        action: 'incident_assigned',
        description: `Incident assigned to ${assignee}`,
        userId: options.assignedBy || 'system',
        details: options,
      });

      await incident.save();

      logger.info(`Incident ${incidentId} assigned to ${assignee}`);
      return incident;
    } catch (error) {
      logger.error('Failed to assign incident:', error);
      throw error;
    }
  }

  /**
   * Update incident status
   */
  async updateIncidentStatus(incidentId, newStatus, options = {}) {
    try {
      const incident = await Incident.findOne({ incidentId });

      if (!incident) {
        throw new Error('Incident not found');
      }

      const oldStatus = incident.status;
      incident.status = newStatus;

      incident.timeline.push({
        timestamp: new Date(),
        action: 'status_changed',
        description: `Status changed from ${oldStatus} to ${newStatus}`,
        userId: options.userId || 'system',
        details: { oldStatus, newStatus, reason: options.reason },
      });

      // Update resolution if incident is closed
      if (newStatus === 'closed' || newStatus === 'resolved') {
        incident.resolution = {
          status: newStatus,
          resolvedAt: new Date(),
          resolvedBy: options.userId || 'system',
          summary: options.summary,
          rootCause: options.rootCause,
          lessonsLearned: options.lessonsLearned,
        };
      }

      await incident.save();

      // Remove from active incidents if closed
      if (newStatus === 'closed') {
        this.activeIncidents.delete(incidentId);
      }

      logger.info(`Incident ${incidentId} status updated to ${newStatus}`);
      return incident;
    } catch (error) {
      logger.error('Failed to update incident status:', error);
      throw error;
    }
  }

  /**
   * Create external ticket (JIRA, ServiceNow, etc.)
   */
  async createExternalTicket(incident) {
    try {
      const results = await TicketingIntegrationManager.createTicket({
        title: incident.title,
        description: incident.description,
        severity: incident.severity,
        category: incident.category,
        source: 'AutoSec',
        metadata: {
          incidentId: incident.incidentId,
          riskScore: incident.riskScore,
          entities: incident.entities,
        },
      });

      // Update incident with external ticket references
      incident.externalTickets = results.results.map(result => ({
        system: result.integration,
        ticketId: result.result.ticketId,
        ticketUrl: result.result.ticketUrl,
        createdAt: new Date(),
      }));

      await incident.save();

      logger.info(`External tickets created for incident ${incident.incidentId}`);
      return results;
    } catch (error) {
      logger.error('Failed to create external ticket:', error);
    }
  }

  /**
   * Load playbooks from database
   */
  async loadPlaybooks() {
    try {
      const playbooks = await Playbook.find({ active: true });
      
      for (const playbook of playbooks) {
        this.playbookLibrary.set(playbook.playbookId, playbook);
      }

      logger.info(`Loaded ${playbooks.length} active playbooks`);
    } catch (error) {
      logger.error('Failed to load playbooks:', error);
    }
  }

  /**
   * Start automated monitoring for escalation and follow-up
   */
  startAutomatedMonitoring() {
    if (!this.config.autoEscalation.enabled) {
      return;
    }

    // Check for incidents that need escalation every 5 minutes
    setInterval(async () => {
      try {
        await this.checkForEscalation();
      } catch (error) {
        logger.error('Error in automated escalation check:', error);
      }
    }, 5 * 60 * 1000);

    logger.info('Automated incident monitoring started');
  }

  /**
   * Check incidents for escalation
   */
  async checkForEscalation() {
    const now = new Date();
    const thresholds = this.config.autoEscalation.timeThresholds;

    for (const [incidentId, incident] of this.activeIncidents) {
      if (incident.status === 'new' || incident.status === 'investigating') {
        const ageMinutes = (now - incident.createdAt) / (1000 * 60);
        const threshold = thresholds[incident.severity] || thresholds.medium;

        if (ageMinutes > threshold) {
          await this.escalateIncident(incidentId, {
            reason: 'Automatic escalation due to time threshold',
            ageMinutes,
            threshold,
          });
        }
      }
    }
  }

  /**
   * Escalate incident
   */
  async escalateIncident(incidentId, options = {}) {
    try {
      const incident = await this.getIncident(incidentId);

      incident.escalationLevel = (incident.escalationLevel || 0) + 1;
      incident.timeline.push({
        timestamp: new Date(),
        action: 'incident_escalated',
        description: `Incident escalated to level ${incident.escalationLevel}`,
        userId: options.userId || 'system',
        details: options,
      });

      await incident.save();

      logger.warn(`Incident ${incidentId} escalated to level ${incident.escalationLevel}`);

      // Trigger escalation playbook if available
      const escalationPlaybooks = await this.findEscalationPlaybooks(incident);
      for (const playbook of escalationPlaybooks) {
        await this.executePlaybook(incidentId, playbook.playbookId, {
          executor: 'escalation',
          escalationLevel: incident.escalationLevel,
        });
      }

      return incident;
    } catch (error) {
      logger.error('Failed to escalate incident:', error);
      throw error;
    }
  }

  /**
   * Utility methods
   */
  async getIncident(incidentId) {
    return await Incident.findOne({ incidentId });
  }

  async getPlaybook(playbookId) {
    return this.playbookLibrary.get(playbookId) || await Playbook.findOne({ playbookId });
  }

  categorizeIncident(threatEvent) {
    const categoryMap = {
      'threat_intelligence_match': 'malware',
      'behavioral_deviation': 'insider_threat',
      'anomaly_detection': 'suspicious_activity',
      'rule_violation': 'policy_violation',
      'correlation_match': 'advanced_threat',
    };
    return categoryMap[threatEvent.eventType] || 'unknown';
  }

  parseAssignmentRules(rulesString) {
    try {
      return JSON.parse(rulesString || '[]');
    } catch (error) {
      logger.error('Failed to parse assignment rules:', error);
      return [];
    }
  }

  evaluateAssignmentRule(rule, incident) {
    // Simplified rule evaluation
    return rule.conditions.every(condition => 
      this.evaluateCondition(
        this.getIncidentFieldValue(incident, condition.field),
        condition.operator,
        condition.value
      )
    );
  }

  async findEscalationPlaybooks(incident) {
    return await Playbook.find({
      active: true,
      'triggers.type': 'escalation',
    });
  }

  async updateIncidentFromExecution(incident, execution) {
    incident.timeline.push({
      timestamp: new Date(),
      action: 'playbook_executed',
      description: `Playbook execution ${execution.status}`,
      userId: execution.executor,
      details: {
        playbookId: execution.playbookId,
        executionId: execution.executionId,
        status: execution.status,
        steps: execution.steps.length,
      },
    });

    await incident.save();
  }

  async requestApproval(incident, playbook) {
    // Placeholder for approval workflow
    logger.info(`Approval requested for playbook ${playbook.playbookId} on incident ${incident.incidentId}`);
  }
}

module.exports = new IncidentResponseService();