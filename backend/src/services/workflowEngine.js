/**
 * Workflow Engine
 * Executes automated response playbooks with step-by-step processing
 */

const logger = require('../config/logger');
const EventEmitter = require('events');

class WorkflowEngine extends EventEmitter {
  constructor() {
    super();
    this.activeExecutions = new Map();
    this.stepProcessors = new Map();
    this.initialized = false;
  }

  /**
   * Initialize the workflow engine
   */
  async initialize() {
    try {
      logger.info('Initializing Workflow Engine...');

      // Register built-in step processors
      this.registerStepProcessors();

      this.initialized = true;
      logger.info('Workflow Engine initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Workflow Engine:', error);
      throw error;
    }
  }

  /**
   * Execute a workflow
   */
  async executeWorkflow(workflow, context) {
    if (!this.initialized) {
      throw new Error('Workflow Engine not initialized');
    }

    const executionId = `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const execution = {
      executionId,
      workflow,
      context,
      status: 'running',
      startTime: new Date(),
      endTime: null,
      steps: [],
      variables: { ...workflow.variables?.reduce((acc, v) => ({ ...acc, [v.name]: v.defaultValue }), {}), ...context.variables },
      errors: [],
      currentStep: null,
    };

    this.activeExecutions.set(executionId, execution);

    try {
      logger.info(`Starting workflow execution ${executionId}`);
      this.emit('execution:started', execution);

      // Execute workflow steps
      await this.executeSteps(execution);

      execution.status = 'completed';
      execution.endTime = new Date();
      
      logger.info(`Workflow execution ${executionId} completed successfully`);
      this.emit('execution:completed', execution);

    } catch (error) {
      execution.status = 'failed';
      execution.endTime = new Date();
      execution.errors.push({
        timestamp: new Date(),
        error: error.message,
        stack: error.stack,
        step: execution.currentStep,
      });

      logger.error(`Workflow execution ${executionId} failed:`, error);
      this.emit('execution:failed', execution, error);
    } finally {
      // Keep execution in memory for a while for debugging
      setTimeout(() => {
        this.activeExecutions.delete(executionId);
      }, 300000); // 5 minutes
    }

    return execution;
  }

  /**
   * Execute workflow steps
   */
  async executeSteps(execution) {
    const { workflow } = execution;
    const stepQueue = [...workflow.steps];
    const completedSteps = new Set();
    const failedSteps = new Set();

    while (stepQueue.length > 0) {
      // Find steps that can be executed (all dependencies met)
      const readySteps = stepQueue.filter(step => 
        !step.dependencies || 
        step.dependencies.every(dep => completedSteps.has(dep))
      );

      if (readySteps.length === 0) {
        // Check for circular dependencies or failed dependencies
        const remainingSteps = stepQueue.filter(step => !completedSteps.has(step.stepId));
        const blockedByFailures = remainingSteps.some(step =>
          step.dependencies?.some(dep => failedSteps.has(dep))
        );

        if (blockedByFailures) {
          throw new Error('Workflow blocked by failed dependency steps');
        } else {
          throw new Error('Circular dependency detected in workflow');
        }
      }

      // Execute ready steps (respecting parallelism)
      const parallelism = Math.min(workflow.parallelism || 1, readySteps.length);
      const stepsToExecute = readySteps.slice(0, parallelism);

      // Remove executed steps from queue
      stepQueue.splice(0, stepsToExecute.length);

      // Execute steps in parallel
      const stepPromises = stepsToExecute.map(step => this.executeStep(execution, step));
      const stepResults = await Promise.allSettled(stepPromises);

      // Process results
      for (let i = 0; i < stepResults.length; i++) {
        const result = stepResults[i];
        const step = stepsToExecute[i];

        if (result.status === 'fulfilled') {
          completedSteps.add(step.stepId);
          execution.steps.push({
            stepId: step.stepId,
            name: step.name,
            status: 'completed',
            startTime: result.value.startTime,
            endTime: result.value.endTime,
            output: result.value.output,
            duration: result.value.endTime - result.value.startTime,
          });
        } else {
          failedSteps.add(step.stepId);
          execution.steps.push({
            stepId: step.stepId,
            name: step.name,
            status: 'failed',
            error: result.reason.message,
            duration: 0,
          });

          // Handle error based on step configuration
          if (step.errorHandling?.onError === 'stop') {
            throw new Error(`Step ${step.stepId} failed: ${result.reason.message}`);
          } else if (step.errorHandling?.onError === 'retry') {
            // Implement retry logic
            const retryResult = await this.retryStep(execution, step);
            if (!retryResult.success) {
              throw new Error(`Step ${step.stepId} failed after retries: ${result.reason.message}`);
            }
          }
          // 'continue' and 'escalate' are handled by continuing execution
        }
      }
    }
  }

  /**
   * Execute a single step
   */
  async executeStep(execution, step) {
    const startTime = new Date();
    execution.currentStep = step.stepId;

    logger.debug(`Executing step ${step.stepId}: ${step.name}`);
    this.emit('step:started', execution, step);

    try {
      // Get step processor
      const processor = this.stepProcessors.get(step.type);
      if (!processor) {
        throw new Error(`No processor found for step type: ${step.type}`);
      }

      // Set up timeout
      const timeout = step.timeout || 300; // 5 minutes default
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`Step timed out after ${timeout} seconds`)), timeout * 1000);
      });

      // Execute step with timeout
      const output = await Promise.race([
        processor(step, execution),
        timeoutPromise
      ]);

      const endTime = new Date();

      // Apply output mapping if configured
      if (step.outputMapping) {
        this.applyOutputMapping(execution, step.outputMapping, output);
      }

      logger.debug(`Step ${step.stepId} completed successfully`);
      this.emit('step:completed', execution, step, output);

      return { startTime, endTime, output };
    } catch (error) {
      const endTime = new Date();
      
      logger.error(`Step ${step.stepId} failed:`, error);
      this.emit('step:failed', execution, step, error);

      throw error;
    }
  }

  /**
   * Retry a failed step
   */
  async retryStep(execution, step) {
    const maxRetries = step.retryPolicy?.maxRetries || 0;
    const retryDelay = step.retryPolicy?.retryDelay || 30;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      logger.info(`Retrying step ${step.stepId}, attempt ${attempt}/${maxRetries}`);

      // Wait before retry
      if (attempt > 1) {
        await new Promise(resolve => setTimeout(resolve, retryDelay * 1000));
      }

      try {
        await this.executeStep(execution, step);
        logger.info(`Step ${step.stepId} succeeded on retry attempt ${attempt}`);
        return { success: true, attempt };
      } catch (error) {
        logger.error(`Step ${step.stepId} retry attempt ${attempt} failed:`, error);
        
        if (attempt === maxRetries) {
          return { success: false, attempt, error };
        }
      }
    }

    return { success: false, attempt: maxRetries };
  }

  /**
   * Apply output mapping to execution variables
   */
  applyOutputMapping(execution, outputMapping, stepOutput) {
    for (const mapping of outputMapping) {
      try {
        const sourceValue = this.getNestedValue(stepOutput, mapping.source);
        let targetValue = sourceValue;

        // Apply transformation if specified
        if (mapping.transform) {
          targetValue = this.applyTransform(sourceValue, mapping.transform);
        }

        this.setNestedValue(execution.variables, mapping.target, targetValue);
      } catch (error) {
        logger.error(`Failed to apply output mapping ${mapping.source} -> ${mapping.target}:`, error);
      }
    }
  }

  /**
   * Get nested value from object using dot notation
   */
  getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  /**
   * Set nested value in object using dot notation
   */
  setNestedValue(obj, path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((current, key) => {
      if (!(key in current)) current[key] = {};
      return current[key];
    }, obj);
    target[lastKey] = value;
  }

  /**
   * Apply data transformation
   */
  applyTransform(value, transform) {
    try {
      switch (transform) {
        case 'toString':
          return String(value);
        case 'toNumber':
          return Number(value);
        case 'toUpperCase':
          return String(value).toUpperCase();
        case 'toLowerCase':
          return String(value).toLowerCase();
        case 'toArray':
          return Array.isArray(value) ? value : [value];
        case 'length':
          return Array.isArray(value) ? value.length : String(value).length;
        default:
          // Try to evaluate as JavaScript expression
          if (transform.startsWith('js:')) {
            const code = transform.substring(3);
            return new Function('value', `return ${code}`)(value);
          }
          return value;
      }
    } catch (error) {
      logger.error(`Failed to apply transform ${transform} to value ${value}:`, error);
      return value;
    }
  }

  /**
   * Register built-in step processors
   */
  registerStepProcessors() {
    // Action step processor
    this.stepProcessors.set('action', async (step, execution) => {
      const { config } = step;
      const action = config.action;

      switch (action) {
        case 'block_ip':
          return await this.processBlockIPAction(config, execution);
        case 'disable_user':
          return await this.processDisableUserAction(config, execution);
        case 'quarantine_file':
          return await this.processQuarantineFileAction(config, execution);
        case 'send_notification':
          return await this.processSendNotificationAction(config, execution);
        case 'create_ticket':
          return await this.processCreateTicketAction(config, execution);
        case 'collect_evidence':
          return await this.processCollectEvidenceAction(config, execution);
        default:
          throw new Error(`Unknown action: ${action}`);
      }
    });

    // Decision step processor
    this.stepProcessors.set('decision', async (step, execution) => {
      const { config } = step;
      const condition = config.condition;
      
      const result = this.evaluateCondition(condition, execution.variables);
      
      return {
        decision: result,
        nextStep: result ? config.trueStep : config.falseStep,
      };
    });

    // Delay step processor
    this.stepProcessors.set('delay', async (step) => {
      const delay = step.config.delay || 30; // seconds
      await new Promise(resolve => setTimeout(resolve, delay * 1000));
      return { delayed: delay };
    });

    // Manual step processor
    this.stepProcessors.set('manual', async (step, execution) => {
      // Create manual task that requires human intervention
      const taskId = `task-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
      
      logger.info(`Manual step ${step.stepId} requires human intervention. Task ID: ${taskId}`);
      
      // In a real implementation, this would create a task in a task management system
      // For now, we'll just log it and mark as pending
      
      return {
        taskId,
        status: 'pending_manual_intervention',
        instructions: step.config.instructions,
      };
    });

    // Notification step processor
    this.stepProcessors.set('notification', async (step, execution) => {
      const { config } = step;
      
      // Send notification through configured channels
      const notifications = [];
      
      if (config.email) {
        notifications.push({ type: 'email', ...config.email });
      }
      
      if (config.slack) {
        notifications.push({ type: 'slack', ...config.slack });
      }
      
      if (config.sms) {
        notifications.push({ type: 'sms', ...config.sms });
      }

      // Process notifications
      const results = [];
      for (const notification of notifications) {
        try {
          const result = await this.sendNotification(notification, execution);
          results.push({ type: notification.type, success: true, result });
        } catch (error) {
          results.push({ type: notification.type, success: false, error: error.message });
        }
      }

      return { notifications: results };
    });

    // Integration step processor
    this.stepProcessors.set('integration', async (step, execution) => {
      const { config } = step;
      const integrationType = config.type;
      const integrationAction = config.action;

      // Route to appropriate integration
      switch (integrationType) {
        case 'firewall':
          return await this.processFirewallIntegration(config, execution);
        case 'siem':
          return await this.processSIEMIntegration(config, execution);
        case 'vulnerability_scanner':
          return await this.processVulnerabilityIntegration(config, execution);
        case 'sdn':
          return await this.processSDNIntegration(config, execution);
        default:
          throw new Error(`Unknown integration type: ${integrationType}`);
      }
    });

    // Parallel step processor
    this.stepProcessors.set('parallel', async (step, execution) => {
      const { config } = step;
      const parallelSteps = config.steps || [];

      // Execute all parallel steps
      const promises = parallelSteps.map(parallelStep => 
        this.executeStep(execution, parallelStep)
      );

      const results = await Promise.allSettled(promises);
      
      return {
        parallelResults: results.map((result, index) => ({
          stepId: parallelSteps[index].stepId,
          status: result.status,
          value: result.status === 'fulfilled' ? result.value : null,
          error: result.status === 'rejected' ? result.reason.message : null,
        }))
      };
    });

    // Loop step processor
    this.stepProcessors.set('loop', async (step, execution) => {
      const { config } = step;
      const loopStep = config.step;
      const condition = config.condition;
      const maxIterations = config.maxIterations || 10;

      const results = [];
      let iteration = 0;

      while (iteration < maxIterations) {
        // Check loop condition
        if (condition && !this.evaluateCondition(condition, execution.variables)) {
          break;
        }

        // Execute loop step
        try {
          const result = await this.executeStep(execution, loopStep);
          results.push({ iteration, success: true, result });
        } catch (error) {
          results.push({ iteration, success: false, error: error.message });
          
          if (config.breakOnError) {
            break;
          }
        }

        iteration++;
      }

      return { iterations: iteration, results };
    });
  }

  /**
   * Process action implementations
   */
  async processBlockIPAction(config, execution) {
    const firewallManager = require('../integrations/firewallIntegrationManager');
    const ipAddress = this.resolveVariable(config.ipAddress, execution.variables);
    
    const result = await firewallManager.blockIP(ipAddress, config.options);
    
    return {
      action: 'block_ip',
      ipAddress,
      success: result.success,
      results: result.results,
    };
  }

  async processDisableUserAction(config, execution) {
    // Placeholder for user management integration
    const username = this.resolveVariable(config.username, execution.variables);
    
    logger.info(`Disabling user: ${username} (placeholder implementation)`);
    
    return {
      action: 'disable_user',
      username,
      success: true,
      message: 'User disabled successfully',
    };
  }

  async processQuarantineFileAction(config, execution) {
    // Placeholder for file quarantine
    const filePath = this.resolveVariable(config.filePath, execution.variables);
    
    logger.info(`Quarantining file: ${filePath} (placeholder implementation)`);
    
    return {
      action: 'quarantine_file',
      filePath,
      success: true,
      message: 'File quarantined successfully',
    };
  }

  async processSendNotificationAction(config, execution) {
    const message = this.resolveVariable(config.message, execution.variables);
    const recipients = this.resolveVariable(config.recipients, execution.variables);
    
    // Send notification
    const result = await this.sendNotification({
      type: config.type || 'email',
      message,
      recipients,
      subject: config.subject,
    }, execution);

    return {
      action: 'send_notification',
      success: true,
      result,
    };
  }

  async processCreateTicketAction(config, execution) {
    const ticketingManager = require('../integrations/ticketingIntegrationManager');
    
    const ticket = {
      title: this.resolveVariable(config.title, execution.variables),
      description: this.resolveVariable(config.description, execution.variables),
      severity: config.severity,
      category: config.category,
    };

    const result = await ticketingManager.createTicket(ticket);
    
    return {
      action: 'create_ticket',
      success: result.success,
      tickets: result.results,
    };
  }

  async processCollectEvidenceAction(config, execution) {
    // Placeholder for evidence collection
    const evidenceType = config.evidenceType;
    const target = this.resolveVariable(config.target, execution.variables);
    
    logger.info(`Collecting ${evidenceType} evidence from ${target} (placeholder implementation)`);
    
    return {
      action: 'collect_evidence',
      evidenceType,
      target,
      success: true,
      evidence: {
        type: evidenceType,
        collected: true,
        timestamp: new Date(),
      },
    };
  }

  /**
   * Process integration calls
   */
  async processFirewallIntegration(config, execution) {
    const firewallManager = require('../integrations/firewallIntegrationManager');
    
    switch (config.action) {
      case 'block_ip': {
        const ipAddress = this.resolveVariable(config.ipAddress, execution.variables);
        return await firewallManager.blockIP(ipAddress, config.options);
      }
      case 'create_rule':
        return await firewallManager.createSecurityRule(config.rule, config.targets);
      default:
        throw new Error(`Unknown firewall action: ${config.action}`);
    }
  }

  async processSIEMIntegration(config, execution) {
    const siemManager = require('../integrations/siemIntegrationManager');
    
    switch (config.action) {
      case 'send_event': {
        const event = this.resolveVariable(config.event, execution.variables);
        return await siemManager.sendEvent(event);
      }
      case 'create_alert': {
        const alert = this.resolveVariable(config.alert, execution.variables);
        return await siemManager.createAlert(alert);
      }
      default:
        throw new Error(`Unknown SIEM action: ${config.action}`);
    }
  }

  async processVulnerabilityIntegration(config, execution) {
    const vulnManager = require('../integrations/vulnerabilityIntegrationManager');
    
    switch (config.action) {
      case 'start_scan':
        return await vulnManager.startScan(config.scanConfig, config.targets);
      case 'get_results': {
        const scanId = this.resolveVariable(config.scanId, execution.variables);
        return await vulnManager.getScanResults(scanId);
      }
      default:
        throw new Error(`Unknown vulnerability scanner action: ${config.action}`);
    }
  }

  async processSDNIntegration(config, execution) {
    const sdnManager = require('../integrations/sdnIntegrationManager');
    
    switch (config.action) {
      case 'block_ip': {
        const ipAddress = this.resolveVariable(config.ipAddress, execution.variables);
        return await sdnManager.blockIP(ipAddress, config.options);
      }
      case 'create_flow_rule':
        return await sdnManager.createFlowRule(config.rule, config.targets);
      default:
        throw new Error(`Unknown SDN action: ${config.action}`);
    }
  }

  /**
   * Send notification
   */
  async sendNotification(notification, execution) {
    // Placeholder for notification service
    logger.info(`Sending ${notification.type} notification: ${notification.message}`);
    
    return {
      type: notification.type,
      sent: true,
      timestamp: new Date(),
    };
  }

  /**
   * Resolve variable value
   */
  resolveVariable(value, variables) {
    if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
      const varName = value.slice(2, -1);
      return this.getNestedValue(variables, varName) || value;
    }
    return value;
  }

  /**
   * Evaluate condition
   */
  evaluateCondition(condition, variables) {
    try {
      const leftValue = this.resolveVariable(condition.left, variables);
      const rightValue = this.resolveVariable(condition.right, variables);
      const operator = condition.operator;

      switch (operator) {
        case 'equals':
          return leftValue === rightValue;
        case 'not_equals':
          return leftValue !== rightValue;
        case 'greater_than':
          return leftValue > rightValue;
        case 'less_than':
          return leftValue < rightValue;
        case 'greater_equal':
          return leftValue >= rightValue;
        case 'less_equal':
          return leftValue <= rightValue;
        case 'contains':
          return String(leftValue).includes(String(rightValue));
        case 'starts_with':
          return String(leftValue).startsWith(String(rightValue));
        case 'ends_with':
          return String(leftValue).endsWith(String(rightValue));
        case 'regex':
          return new RegExp(rightValue).test(String(leftValue));
        case 'in':
          return Array.isArray(rightValue) && rightValue.includes(leftValue);
        default:
          return false;
      }
    } catch (error) {
      logger.error('Error evaluating condition:', error);
      return false;
    }
  }

  /**
   * Get active executions
   */
  getActiveExecutions() {
    return Array.from(this.activeExecutions.values());
  }

  /**
   * Get execution by ID
   */
  getExecution(executionId) {
    return this.activeExecutions.get(executionId);
  }

  /**
   * Stop execution
   */
  async stopExecution(executionId, reason = 'Manual stop') {
    const execution = this.activeExecutions.get(executionId);
    
    if (execution && execution.status === 'running') {
      execution.status = 'stopped';
      execution.endTime = new Date();
      execution.errors.push({
        timestamp: new Date(),
        error: `Execution stopped: ${reason}`,
        step: execution.currentStep,
      });

      logger.info(`Workflow execution ${executionId} stopped: ${reason}`);
      this.emit('execution:stopped', execution, reason);
    }

    return execution;
  }
}

module.exports = WorkflowEngine;