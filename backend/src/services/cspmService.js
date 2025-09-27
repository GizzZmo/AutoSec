/**
 * Cloud Security Posture Management (CSPM) Service
 * Continuous assessment of cloud security configurations and compliance
 */

const logger = require('../config/logger');

class CSPMService {
  constructor() {
    this.cloudProviders = new Map([
      ['aws', {
        name: 'Amazon Web Services',
        scanner: this.scanAWSResources.bind(this)
      }],
      ['azure', {
        name: 'Microsoft Azure',
        scanner: this.scanAzureResources.bind(this)
      }],
      ['gcp', {
        name: 'Google Cloud Platform',
        scanner: this.scanGCPResources.bind(this)
      }],
      ['kubernetes', {
        name: 'Kubernetes',
        scanner: this.scanKubernetesResources.bind(this)
      }]
    ]);

    this.complianceFrameworks = new Map([
      ['cis', {
        name: 'CIS Benchmarks',
        rules: this.getCISRules()
      }],
      ['nist', {
        name: 'NIST Cybersecurity Framework',
        rules: this.getNISTRules()
      }],
      ['pci', {
        name: 'PCI DSS',
        rules: this.getPCIRules()
      }],
      ['sox', {
        name: 'Sarbanes-Oxley',
        rules: this.getSOXRules()
      }],
      ['hipaa', {
        name: 'HIPAA',
        rules: this.getHIPAARules()
      }]
    ]);

    this.riskLevels = {
      CRITICAL: 'critical',
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
      INFO: 'info'
    };

    this.scanSchedule = new Map();
    this.initializeDefaultPolicies();
  }

  /**
   * Perform comprehensive CSPM assessment
   */
  async performAssessment(assessmentConfig) {
    try {
      const {
        cloudProviders = ['aws', 'azure', 'gcp', 'kubernetes'],
        complianceFrameworks = ['cis', 'nist'],
        resourceTypes = [],
        regions = [],
        userId
      } = assessmentConfig;

      logger.info(`Starting CSPM assessment for providers: ${cloudProviders.join(', ')}`);

      const startTime = Date.now();
      const results = {
        assessmentId: this.generateAssessmentId(),
        startTime: new Date(startTime),
        providers: [],
        summary: {
          totalResources: 0,
          compliantResources: 0,
          nonCompliantResources: 0,
          criticalFindings: 0,
          highFindings: 0,
          mediumFindings: 0,
          lowFindings: 0
        },
        compliance: {},
        recommendations: []
      };

      // Scan each cloud provider
      for (const provider of cloudProviders) {
        if (this.cloudProviders.has(provider)) {
          const providerResults = await this.scanCloudProvider(provider, {
            complianceFrameworks,
            resourceTypes,
            regions
          });
          
          results.providers.push(providerResults);
          this.aggregateResults(results.summary, providerResults);
        }
      }

      // Generate compliance scores
      for (const framework of complianceFrameworks) {
        results.compliance[framework] = await this.calculateComplianceScore(results, framework);
      }

      // Generate remediation recommendations
      results.recommendations = await this.generateRecommendations(results);

      results.endTime = new Date();
      results.duration = Date.now() - startTime;

      // Save assessment results
      await this.saveAssessmentResults(results, userId);

      logger.info(`CSMP assessment completed in ${results.duration}ms`);
      return results;

    } catch (error) {
      logger.error('Error performing CSPM assessment:', error);
      throw error;
    }
  }

  /**
   * Scan resources for a specific cloud provider
   */
  async scanCloudProvider(provider, options) {
    const providerConfig = this.cloudProviders.get(provider);
    if (!providerConfig) {
      throw new Error(`Unsupported cloud provider: ${provider}`);
    }

    logger.info(`Scanning ${providerConfig.name} resources`);

    const results = {
      provider,
      name: providerConfig.name,
      resources: [],
      findings: [],
      summary: {
        totalResources: 0,
        compliantResources: 0,
        nonCompliantResources: 0,
        findingsByRisk: {}
      }
    };

    try {
      const resources = await providerConfig.scanner(options);
      results.resources = resources;
      results.summary.totalResources = resources.length;

      // Evaluate each resource against compliance rules
      for (const resource of resources) {
        const resourceFindings = await this.evaluateResource(resource, options.complianceFrameworks);
        results.findings.push(...resourceFindings);

        // Update compliance status
        if (resourceFindings.length === 0) {
          results.summary.compliantResources++;
        } else {
          results.summary.nonCompliantResources++;
        }
      }

      // Aggregate findings by risk level
      results.summary.findingsByRisk = this.aggregateFindingsByRisk(results.findings);

    } catch (error) {
      logger.error(`Error scanning ${provider}:`, error);
      results.error = error.message;
    }

    return results;
  }

  /**
   * Evaluate a resource against compliance rules
   */
  async evaluateResource(resource, frameworks) {
    const findings = [];

    for (const framework of frameworks) {
      const rules = this.complianceFrameworks.get(framework)?.rules || [];
      
      for (const rule of rules) {
        if (this.isRuleApplicable(rule, resource)) {
          const result = await this.evaluateRule(rule, resource);
          
          if (!result.compliant) {
            findings.push({
              id: this.generateFindingId(),
              rule: rule.id,
              framework,
              title: rule.title,
              description: rule.description,
              riskLevel: rule.riskLevel,
              resource: {
                id: resource.id,
                type: resource.type,
                name: resource.name,
                provider: resource.provider,
                region: resource.region
              },
              details: result.details,
              remediation: rule.remediation,
              evidence: result.evidence,
              discoveredAt: new Date()
            });
          }
        }
      }
    }

    return findings;
  }

  /**
   * Scan AWS resources
   */
  async scanAWSResources(options) {
    const resources = [];

    try {
      // Mock AWS resource scanning - in production, use AWS SDK
      const mockResources = [
        {
          id: 'sg-12345',
          type: 'SecurityGroup',
          name: 'default-sg',
          provider: 'aws',
          region: 'us-east-1',
          config: {
            rules: [
              { protocol: 'tcp', port: 22, source: '0.0.0.0/0' },
              { protocol: 'tcp', port: 80, source: '0.0.0.0/0' }
            ]
          }
        },
        {
          id: 'i-67890',
          type: 'EC2Instance',
          name: 'web-server-1',
          provider: 'aws',
          region: 'us-east-1',
          config: {
            instanceType: 't3.micro',
            securityGroups: ['sg-12345'],
            publicIp: '203.0.113.1',
            encrypted: false
          }
        },
        {
          id: 'bucket-98765',
          type: 'S3Bucket',
          name: 'my-data-bucket',
          provider: 'aws',
          region: 'us-east-1',
          config: {
            publicRead: true,
            publicWrite: false,
            encryption: false,
            versioning: false
          }
        }
      ];

      resources.push(...mockResources);
      logger.info(`Found ${resources.length} AWS resources`);

    } catch (error) {
      logger.error('Error scanning AWS resources:', error);
    }

    return resources;
  }

  /**
   * Scan Kubernetes resources
   */
  async scanKubernetesResources(options) {
    const resources = [];

    try {
      // Mock Kubernetes resource scanning - in production, use Kubernetes client
      const mockResources = [
        {
          id: 'pod-12345',
          type: 'Pod',
          name: 'autosec-backend-xyz',
          provider: 'kubernetes',
          namespace: 'autosec',
          config: {
            securityContext: {
              runAsNonRoot: true,
              runAsUser: 1001,
              readOnlyRootFilesystem: true
            },
            containers: [{
              name: 'backend',
              image: 'autosec/backend:1.0.0',
              securityContext: {
                allowPrivilegeEscalation: false,
                capabilities: { drop: ['ALL'] }
              }
            }]
          }
        },
        {
          id: 'service-67890',
          type: 'Service',
          name: 'autosec-backend',
          provider: 'kubernetes',
          namespace: 'autosec',
          config: {
            type: 'ClusterIP',
            ports: [{ port: 8080, targetPort: 8080 }]
          }
        },
        {
          id: 'networkpolicy-111',
          type: 'NetworkPolicy',
          name: 'default-deny',
          provider: 'kubernetes',
          namespace: 'autosec',
          config: {
            podSelector: {},
            policyTypes: ['Ingress', 'Egress']
          }
        }
      ];

      resources.push(...mockResources);
      logger.info(`Found ${resources.length} Kubernetes resources`);

    } catch (error) {
      logger.error('Error scanning Kubernetes resources:', error);
    }

    return resources;
  }

  /**
   * Get CIS Benchmark rules
   */
  getCISRules() {
    return [
      {
        id: 'CIS-AWS-1.1',
        title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
        description: 'Security groups should not allow unrestricted access to SSH port 22',
        riskLevel: this.riskLevels.HIGH,
        resourceTypes: ['SecurityGroup'],
        providers: ['aws'],
        check: (resource) => {
          if (resource.type !== 'SecurityGroup') return { compliant: true };
          
          const hasUnrestrictedSSH = resource.config.rules?.some(rule => 
            rule.port === 22 && rule.source === '0.0.0.0/0'
          );
          
          return {
            compliant: !hasUnrestrictedSSH,
            details: hasUnrestrictedSSH ? 'Security group allows SSH access from anywhere' : null,
            evidence: hasUnrestrictedSSH ? resource.config.rules : null
          };
        },
        remediation: {
          description: 'Restrict SSH access to specific IP ranges or remove the rule',
          steps: [
            'Identify the security group with unrestricted SSH access',
            'Modify the inbound rule to restrict source to specific IP ranges',
            'Consider using AWS Systems Manager Session Manager for secure access'
          ]
        }
      },
      {
        id: 'CIS-AWS-2.1',
        title: 'Ensure S3 buckets are not publicly readable',
        description: 'S3 buckets should not allow public read access',
        riskLevel: this.riskLevels.CRITICAL,
        resourceTypes: ['S3Bucket'],
        providers: ['aws'],
        check: (resource) => {
          if (resource.type !== 'S3Bucket') return { compliant: true };
          
          const isPublicRead = resource.config.publicRead === true;
          
          return {
            compliant: !isPublicRead,
            details: isPublicRead ? 'S3 bucket allows public read access' : null,
            evidence: isPublicRead ? { publicRead: resource.config.publicRead } : null
          };
        },
        remediation: {
          description: 'Remove public read access from S3 bucket',
          steps: [
            'Navigate to S3 console',
            'Select the bucket with public access',
            'Go to Permissions tab',
            'Block all public access',
            'Update bucket policy to remove public statements'
          ]
        }
      },
      {
        id: 'CIS-K8S-5.1.3',
        title: 'Minimize the admission of containers with allowPrivilegeEscalation',
        description: 'Containers should not allow privilege escalation',
        riskLevel: this.riskLevels.HIGH,
        resourceTypes: ['Pod'],
        providers: ['kubernetes'],
        check: (resource) => {
          if (resource.type !== 'Pod') return { compliant: true };
          
          const hasPrivilegeEscalation = resource.config.containers?.some(container =>
            container.securityContext?.allowPrivilegeEscalation !== false
          );
          
          return {
            compliant: !hasPrivilegeEscalation,
            details: hasPrivilegeEscalation ? 'Pod allows privilege escalation' : null,
            evidence: hasPrivilegeEscalation ? resource.config.containers : null
          };
        },
        remediation: {
          description: 'Set allowPrivilegeEscalation to false for all containers',
          steps: [
            'Update Pod specification',
            'Set securityContext.allowPrivilegeEscalation to false',
            'Apply the changes to the cluster'
          ]
        }
      }
    ];
  }

  /**
   * Calculate compliance score for a framework
   */
  async calculateComplianceScore(results, framework) {
    const frameworkFindings = results.providers.flatMap(provider => 
      provider.findings.filter(finding => finding.framework === framework)
    );
    
    const totalRules = this.complianceFrameworks.get(framework)?.rules.length || 1;
    const failedRules = new Set(frameworkFindings.map(f => f.rule)).size;
    const passedRules = totalRules - failedRules;
    
    const score = Math.round((passedRules / totalRules) * 100);
    
    return {
      framework,
      score,
      totalRules,
      passedRules,
      failedRules,
      findings: frameworkFindings.length,
      status: this.getComplianceStatus(score)
    };
  }

  /**
   * Generate remediation recommendations
   */
  async generateRecommendations(results) {
    const recommendations = [];
    const findingsByRisk = {};

    // Group findings by risk level
    results.providers.forEach(provider => {
      provider.findings.forEach(finding => {
        if (!findingsByRisk[finding.riskLevel]) {
          findingsByRisk[finding.riskLevel] = [];
        }
        findingsByRisk[finding.riskLevel].push(finding);
      });
    });

    // Generate recommendations for each risk level
    for (const [riskLevel, findings] of Object.entries(findingsByRisk)) {
      if (findings.length > 0) {
        recommendations.push({
          priority: this.getRiskPriority(riskLevel),
          riskLevel,
          title: `Address ${findings.length} ${riskLevel} security findings`,
          description: `Immediate attention required for ${riskLevel} risk issues`,
          findings: findings.slice(0, 5), // Top 5 for summary
          totalFindings: findings.length,
          estimatedEffort: this.estimateRemediationEffort(findings),
          actions: this.getRecommendedActions(riskLevel, findings)
        });
      }
    }

    return recommendations.sort((a, b) => a.priority - b.priority);
  }

  /**
   * Schedule regular CSPM scans
   */
  async scheduleAssessment(scheduleConfig) {
    const {
      name,
      schedule, // cron expression
      cloudProviders,
      complianceFrameworks,
      userId,
      enabled = true
    } = scheduleConfig;

    const scheduleId = `cspm_${userId}_${Date.now()}`;
    
    const ScheduledAssessment = require('../models/ScheduledAssessment');
    const scheduledAssessment = new ScheduledAssessment({
      scheduleId,
      name,
      userId,
      schedule: {
        cron: schedule,
        enabled
      },
      config: {
        cloudProviders,
        complianceFrameworks
      },
      metadata: {
        createdAt: new Date(),
        nextRun: this.getNextRunTime(schedule)
      }
    });

    await scheduledAssessment.save();
    
    // TODO: Implement actual cron scheduling
    this.scanSchedule.set(scheduleId, scheduledAssessment);
    
    logger.info(`CSPM assessment scheduled: ${scheduleId}`);
    return scheduledAssessment;
  }

  /**
   * Helper methods
   */
  initializeDefaultPolicies() {
    logger.info('CSPM Service initialized with default compliance policies');
  }

  generateAssessmentId() {
    return `assess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateFindingId() {
    return `finding_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  isRuleApplicable(rule, resource) {
    return rule.resourceTypes.includes(resource.type) && 
           rule.providers.includes(resource.provider);
  }

  async evaluateRule(rule, resource) {
    try {
      return rule.check(resource);
    } catch (error) {
      logger.error(`Error evaluating rule ${rule.id}:`, error);
      return { compliant: true, error: error.message };
    }
  }

  aggregateResults(summary, providerResults) {
    summary.totalResources += providerResults.summary.totalResources;
    summary.compliantResources += providerResults.summary.compliantResources;
    summary.nonCompliantResources += providerResults.summary.nonCompliantResources;

    // Aggregate findings by risk level
    Object.entries(providerResults.summary.findingsByRisk).forEach(([risk, count]) => {
      summary[`${risk}Findings`] = (summary[`${risk}Findings`] || 0) + count;
    });
  }

  aggregateFindingsByRisk(findings) {
    return findings.reduce((acc, finding) => {
      acc[finding.riskLevel] = (acc[finding.riskLevel] || 0) + 1;
      return acc;
    }, {});
  }

  getComplianceStatus(score) {
    if (score >= 90) return 'excellent';
    if (score >= 80) return 'good';
    if (score >= 70) return 'fair';
    if (score >= 60) return 'poor';
    return 'critical';
  }

  getRiskPriority(riskLevel) {
    const priorities = {
      critical: 1,
      high: 2,
      medium: 3,
      low: 4,
      info: 5
    };
    return priorities[riskLevel] || 99;
  }

  estimateRemediationEffort(findings) {
    const effortMap = {
      critical: 8, // hours
      high: 4,
      medium: 2,
      low: 1,
      info: 0.5
    };

    return findings.reduce((total, finding) => {
      return total + (effortMap[finding.riskLevel] || 1);
    }, 0);
  }

  getRecommendedActions(riskLevel, findings) {
    const actions = [];
    
    if (riskLevel === 'critical') {
      actions.push('Immediate remediation required within 24 hours');
      actions.push('Consider temporary access restrictions');
    } else if (riskLevel === 'high') {
      actions.push('Remediate within 7 days');
      actions.push('Review and update security policies');
    } else {
      actions.push('Include in next maintenance window');
      actions.push('Consider automation for similar issues');
    }

    return actions;
  }

  getNextRunTime(cronExpression) {
    // Simplified - use proper cron parser in production
    return new Date(Date.now() + 24 * 60 * 60 * 1000);
  }

  async saveAssessmentResults(results, userId) {
    try {
      const CSPMAssessment = require('../models/CSPMAssessment');
      const assessment = new CSPMAssessment({
        assessmentId: results.assessmentId,
        userId,
        results,
        status: 'completed'
      });
      
      await assessment.save();
      logger.info(`CSPM assessment results saved: ${results.assessmentId}`);
    } catch (error) {
      logger.error('Error saving CSPM assessment results:', error);
    }
  }

  // Placeholder methods for other cloud providers
  async scanAzureResources(options) { return []; }
  async scanGCPResources(options) { return []; }
  
  getNISTRules() { return []; }
  getPCIRules() { return []; }
  getSOXRules() { return []; }
  getHIPAARules() { return []; }
}

module.exports = new CSPMService();