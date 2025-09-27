/**
 * Container Security Service
 * Provides container security scanning and runtime protection
 */

const logger = require('../config/logger');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

class ContainerSecurityService {
  constructor() {
    this.scanners = new Map([
      ['trivy', {
        name: 'Trivy',
        command: 'trivy',
        scanner: this.scanWithTrivy.bind(this)
      }],
      ['clair', {
        name: 'Clair',
        command: 'clairctl',
        scanner: this.scanWithClair.bind(this)
      }],
      ['grype', {
        name: 'Grype',
        command: 'grype',
        scanner: this.scanWithGrype.bind(this)
      }]
    ]);

    this.runtimeProtections = new Map([
      ['falco', {
        name: 'Falco',
        type: 'runtime_detection',
        handler: this.handleFalcoAlert.bind(this)
      }],
      ['apparmor', {
        name: 'AppArmor',
        type: 'access_control',
        handler: this.handleAppArmorViolation.bind(this)
      }],
      ['seccomp', {
        name: 'Seccomp',
        type: 'syscall_filtering',
        handler: this.handleSeccompViolation.bind(this)
      }]
    ]);

    this.vulnerabilityDatabase = new Map();
    this.runtimePolicies = new Map();
    this.activeScans = new Map();
    
    this.initializeDefaultPolicies();
  }

  /**
   * Scan container image for vulnerabilities
   */
  async scanContainerImage(scanRequest) {
    try {
      const {
        imageUrl,
        scanType = 'full',
        scanner = 'trivy',
        userId,
        registryCredentials
      } = scanRequest;

      logger.info(`Starting container scan for image: ${imageUrl}`);

      const scanId = this.generateScanId();
      const startTime = Date.now();

      // Record scan start
      this.activeScans.set(scanId, {
        scanId,
        imageUrl,
        scanner,
        status: 'running',
        startTime: new Date(startTime),
        userId
      });

      // Perform the scan
      const scanResults = await this.performImageScan(imageUrl, scanner, scanType, registryCredentials);
      
      // Analyze results
      const analysis = await this.analyzeVulnerabilities(scanResults);
      
      // Generate recommendations
      const recommendations = await this.generateSecurityRecommendations(analysis);
      
      // Calculate risk score
      const riskScore = this.calculateImageRiskScore(analysis);

      const finalResults = {
        scanId,
        imageUrl,
        scanner,
        scanType,
        status: 'completed',
        startTime: new Date(startTime),
        endTime: new Date(),
        duration: Date.now() - startTime,
        vulnerabilities: scanResults.vulnerabilities || [],
        secrets: scanResults.secrets || [],
        misconfigurations: scanResults.misconfigurations || [],
        analysis,
        recommendations,
        riskScore,
        metadata: {
          imageSize: scanResults.imageSize,
          layers: scanResults.layers,
          baseImage: scanResults.baseImage,
          totalPackages: scanResults.totalPackages
        }
      };

      // Save scan results
      await this.saveScanResults(finalResults, userId);
      
      // Update active scans
      this.activeScans.delete(scanId);

      logger.info(`Container scan completed: ${scanId} (${finalResults.duration}ms)`);
      return finalResults;

    } catch (error) {
      logger.error('Error scanning container image:', error);
      throw error;
    }
  }

  /**
   * Perform actual image scanning using specified scanner
   */
  async performImageScan(imageUrl, scanner, scanType, credentials) {
    const scannerConfig = this.scanners.get(scanner);
    if (!scannerConfig) {
      throw new Error(`Unsupported scanner: ${scanner}`);
    }

    return await scannerConfig.scanner(imageUrl, scanType, credentials);
  }

  /**
   * Scan with Trivy scanner
   */
  async scanWithTrivy(imageUrl, scanType, credentials) {
    return new Promise((resolve, reject) => {
      const outputFile = `/tmp/trivy_scan_${Date.now()}.json`;
      let command = `trivy image --format json --output ${outputFile}`;
      
      if (scanType === 'quick') {
        command += ' --security-checks vuln';
      } else {
        command += ' --security-checks vuln,config,secret';
      }
      
      command += ` ${imageUrl}`;

      exec(command, async (error, stdout, stderr) => {
        if (error) {
          logger.error('Trivy scan error:', error);
          reject(error);
          return;
        }

        try {
          const rawResults = await fs.readFile(outputFile, 'utf8');
          const trivyResults = JSON.parse(rawResults);
          
          // Clean up temp file
          await fs.unlink(outputFile).catch(() => {});
          
          resolve(this.parseTrivyResults(trivyResults));
        } catch (parseError) {
          logger.error('Error parsing Trivy results:', parseError);
          reject(parseError);
        }
      });
    });
  }

  /**
   * Parse Trivy scan results
   */
  parseTrivyResults(trivyResults) {
    const vulnerabilities = [];
    const secrets = [];
    const misconfigurations = [];
    
    if (trivyResults.Results) {
      for (const result of trivyResults.Results) {
        // Parse vulnerabilities
        if (result.Vulnerabilities) {
          for (const vuln of result.Vulnerabilities) {
            vulnerabilities.push({
              id: vuln.VulnerabilityID,
              package: vuln.PkgName,
              version: vuln.InstalledVersion,
              fixedVersion: vuln.FixedVersion,
              severity: vuln.Severity,
              title: vuln.Title,
              description: vuln.Description,
              references: vuln.References || [],
              cvss: vuln.CVSS,
              target: result.Target
            });
          }
        }

        // Parse secrets
        if (result.Secrets) {
          for (const secret of result.Secrets) {
            secrets.push({
              type: secret.RuleID,
              category: secret.Category,
              severity: secret.Severity,
              title: secret.Title,
              startLine: secret.StartLine,
              endLine: secret.EndLine,
              code: secret.Code?.Lines || [],
              target: result.Target
            });
          }
        }

        // Parse misconfigurations
        if (result.Misconfigurations) {
          for (const misconfig of result.Misconfigurations) {
            misconfigurations.push({
              id: misconfig.ID,
              type: misconfig.Type,
              title: misconfig.Title,
              description: misconfig.Description,
              severity: misconfig.Severity,
              message: misconfig.Message,
              resolution: misconfig.Resolution,
              target: result.Target
            });
          }
        }
      }
    }

    return {
      vulnerabilities,
      secrets,
      misconfigurations,
      metadata: trivyResults.Metadata || {}
    };
  }

  /**
   * Analyze vulnerability results
   */
  async analyzeVulnerabilities(scanResults) {
    const analysis = {
      summary: {
        total: scanResults.vulnerabilities.length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0
      },
      topVulnerabilities: [],
      packageAnalysis: {},
      secretsFound: scanResults.secrets.length,
      misconfigurationsFound: scanResults.misconfigurations.length,
      trends: {}
    };

    // Analyze vulnerabilities by severity
    scanResults.vulnerabilities.forEach(vuln => {
      const severity = vuln.severity.toLowerCase();
      if (analysis.summary.hasOwnProperty(severity)) {
        analysis.summary[severity]++;
      } else {
        analysis.summary.unknown++;
      }
    });

    // Find top vulnerabilities (by CVSS score)
    analysis.topVulnerabilities = scanResults.vulnerabilities
      .filter(v => v.cvss && v.cvss.nvd && v.cvss.nvd.V3Score)
      .sort((a, b) => (b.cvss.nvd.V3Score || 0) - (a.cvss.nvd.V3Score || 0))
      .slice(0, 10);

    // Analyze packages with vulnerabilities
    const packageVulns = {};
    scanResults.vulnerabilities.forEach(vuln => {
      const pkg = vuln.package;
      if (!packageVulns[pkg]) {
        packageVulns[pkg] = {
          package: pkg,
          totalVulns: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        };
      }
      
      packageVulns[pkg].totalVulns++;
      const severity = vuln.severity.toLowerCase();
      if (packageVulns[pkg].hasOwnProperty(severity)) {
        packageVulns[pkg][severity]++;
      }
    });

    analysis.packageAnalysis = Object.values(packageVulns)
      .sort((a, b) => b.totalVulns - a.totalVulns)
      .slice(0, 20);

    return analysis;
  }

  /**
   * Generate security recommendations
   */
  async generateSecurityRecommendations(analysis) {
    const recommendations = [];

    // Critical vulnerabilities
    if (analysis.summary.critical > 0) {
      recommendations.push({
        priority: 'critical',
        category: 'vulnerabilities',
        title: `Address ${analysis.summary.critical} critical vulnerabilities`,
        description: 'Critical vulnerabilities require immediate attention',
        actions: [
          'Update affected packages to fixed versions',
          'Apply security patches',
          'Consider using alternative packages if fixes unavailable',
          'Implement additional runtime protections'
        ]
      });
    }

    // High severity vulnerabilities
    if (analysis.summary.high > 5) {
      recommendations.push({
        priority: 'high',
        category: 'vulnerabilities',
        title: `${analysis.summary.high} high-severity vulnerabilities found`,
        description: 'High-severity vulnerabilities should be addressed promptly',
        actions: [
          'Plan security updates for high-risk packages',
          'Review package dependencies',
          'Consider vulnerability scanning in CI/CD pipeline'
        ]
      });
    }

    // Secrets found
    if (analysis.secretsFound > 0) {
      recommendations.push({
        priority: 'critical',
        category: 'secrets',
        title: `${analysis.secretsFound} secrets detected in image`,
        description: 'Secrets in container images pose significant security risks',
        actions: [
          'Remove hardcoded secrets from image',
          'Use secret management systems (Kubernetes secrets, HashiCorp Vault)',
          'Implement secret scanning in build pipeline',
          'Rotate any exposed credentials'
        ]
      });
    }

    // Misconfigurations
    if (analysis.misconfigurationsFound > 0) {
      recommendations.push({
        priority: 'medium',
        category: 'configuration',
        title: `${analysis.misconfigurationsFound} security misconfigurations found`,
        description: 'Security misconfigurations can expose the container to attacks',
        actions: [
          'Review and fix security misconfigurations',
          'Use security benchmarks (CIS, NIST)',
          'Implement policy-as-code validation',
          'Enable runtime security monitoring'
        ]
      });
    }

    // Package recommendations
    const topPackages = analysis.packageAnalysis.slice(0, 3);
    if (topPackages.length > 0) {
      recommendations.push({
        priority: 'medium',
        category: 'packages',
        title: 'Update vulnerable packages',
        description: `Top vulnerable packages: ${topPackages.map(p => p.package).join(', ')}`,
        actions: [
          'Update package versions to latest secure releases',
          'Review package dependencies for alternatives',
          'Monitor package security advisories',
          'Consider using minimal base images'
        ]
      });
    }

    return recommendations.sort((a, b) => {
      const priorities = { critical: 1, high: 2, medium: 3, low: 4 };
      return priorities[a.priority] - priorities[b.priority];
    });
  }

  /**
   * Calculate image risk score
   */
  calculateImageRiskScore(analysis) {
    let score = 0;
    
    // Vulnerability scoring
    score += analysis.summary.critical * 10;
    score += analysis.summary.high * 5;
    score += analysis.summary.medium * 2;
    score += analysis.summary.low * 0.5;
    
    // Secrets penalty
    score += analysis.secretsFound * 15;
    
    // Misconfiguration penalty
    score += analysis.misconfigurationsFound * 3;
    
    // Normalize to 0-100 scale
    const maxScore = 100;
    const normalizedScore = Math.min(score, maxScore);
    
    return {
      score: Math.round(normalizedScore),
      level: this.getRiskLevel(normalizedScore),
      factors: {
        vulnerabilities: {
          critical: analysis.summary.critical,
          high: analysis.summary.high,
          medium: analysis.summary.medium,
          low: analysis.summary.low
        },
        secrets: analysis.secretsFound,
        misconfigurations: analysis.misconfigurationsFound
      }
    };
  }

  /**
   * Runtime protection: Handle Falco security alerts
   */
  async handleFalcoAlert(alert) {
    try {
      logger.warn(`Falco runtime alert: ${alert.rule}`, {
        priority: alert.priority,
        container: alert.output_fields?.container_name,
        namespace: alert.output_fields?.k8s_ns_name,
        pod: alert.output_fields?.k8s_pod_name
      });

      const runtimeEvent = {
        id: this.generateEventId(),
        type: 'runtime_alert',
        source: 'falco',
        rule: alert.rule,
        priority: alert.priority,
        timestamp: new Date(alert.time),
        container: {
          name: alert.output_fields?.container_name,
          image: alert.output_fields?.container_image,
          id: alert.output_fields?.container_id
        },
        kubernetes: {
          namespace: alert.output_fields?.k8s_ns_name,
          pod: alert.output_fields?.k8s_pod_name,
          deployment: alert.output_fields?.k8s_deployment_name
        },
        details: alert.output,
        rawAlert: alert
      };

      // Save runtime event
      await this.saveRuntimeEvent(runtimeEvent);

      // Take automatic response if configured
      await this.handleRuntimeResponse(runtimeEvent);

      return runtimeEvent;

    } catch (error) {
      logger.error('Error handling Falco alert:', error);
      throw error;
    }
  }

  /**
   * Handle runtime security responses
   */
  async handleRuntimeResponse(runtimeEvent) {
    const responsePolicy = this.getRuntimeResponsePolicy(runtimeEvent);
    
    if (!responsePolicy) {
      return;
    }

    logger.info(`Executing runtime response: ${responsePolicy.action}`, {
      eventId: runtimeEvent.id,
      rule: runtimeEvent.rule
    });

    switch (responsePolicy.action) {
      case 'alert_only':
        // Already logged, no additional action
        break;
        
      case 'kill_container':
        await this.killContainer(runtimeEvent.container.id);
        break;
        
      case 'quarantine_pod':
        await this.quarantinePod(runtimeEvent.kubernetes.namespace, runtimeEvent.kubernetes.pod);
        break;
        
      case 'scale_down':
        await this.scaleDownDeployment(runtimeEvent.kubernetes.namespace, runtimeEvent.kubernetes.deployment);
        break;
        
      case 'network_isolate':
        await this.isolateNetworkTraffic(runtimeEvent.kubernetes.namespace, runtimeEvent.kubernetes.pod);
        break;
        
      default:
        logger.warn(`Unknown runtime response action: ${responsePolicy.action}`);
    }
  }

  /**
   * Initialize default runtime protection policies
   */
  initializeDefaultPolicies() {
    // High-risk rules that require immediate response
    this.runtimePolicies.set('Terminal shell in container', {
      action: 'quarantine_pod',
      severity: 'high',
      description: 'Interactive shell detected in container'
    });

    this.runtimePolicies.set('File opened for writing in /etc', {
      action: 'alert_only',
      severity: 'medium',
      description: 'Write access to system configuration directory'
    });

    this.runtimePolicies.set('Sensitive file opened for reading', {
      action: 'alert_only',
      severity: 'medium',
      description: 'Access to sensitive system files'
    });

    this.runtimePolicies.set('Unexpected network connection', {
      action: 'network_isolate',
      severity: 'high',
      description: 'Suspicious network activity detected'
    });

    logger.info('Container security runtime policies initialized');
  }

  /**
   * Helper methods
   */
  generateScanId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateEventId() {
    return `event_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
  }

  getRuntimeResponsePolicy(runtimeEvent) {
    return this.runtimePolicies.get(runtimeEvent.rule);
  }

  async saveScanResults(results, userId) {
    try {
      const ContainerScan = require('../models/ContainerScan');
      const scan = new ContainerScan({
        scanId: results.scanId,
        userId,
        imageUrl: results.imageUrl,
        scanner: results.scanner,
        results,
        status: 'completed'
      });
      
      await scan.save();
      logger.info(`Container scan results saved: ${results.scanId}`);
    } catch (error) {
      logger.error('Error saving container scan results:', error);
    }
  }

  async saveRuntimeEvent(event) {
    try {
      const RuntimeEvent = require('../models/RuntimeEvent');
      const runtimeEvent = new RuntimeEvent({
        eventId: event.id,
        type: event.type,
        source: event.source,
        rule: event.rule,
        priority: event.priority,
        container: event.container,
        kubernetes: event.kubernetes,
        details: event.details,
        timestamp: event.timestamp
      });
      
      await runtimeEvent.save();
      logger.info(`Runtime event saved: ${event.id}`);
    } catch (error) {
      logger.error('Error saving runtime event:', error);
    }
  }

  // Placeholder methods for runtime response actions
  async killContainer(containerId) {
    logger.info(`Would kill container: ${containerId}`);
  }

  async quarantinePod(namespace, podName) {
    logger.info(`Would quarantine pod: ${namespace}/${podName}`);
  }

  async scaleDownDeployment(namespace, deploymentName) {
    logger.info(`Would scale down deployment: ${namespace}/${deploymentName}`);
  }

  async isolateNetworkTraffic(namespace, podName) {
    logger.info(`Would isolate network for pod: ${namespace}/${podName}`);
  }

  // Placeholder methods for other scanners
  async scanWithClair(imageUrl, scanType, credentials) {
    return { vulnerabilities: [], secrets: [], misconfigurations: [] };
  }

  async scanWithGrype(imageUrl, scanType, credentials) {
    return { vulnerabilities: [], secrets: [], misconfigurations: [] };
  }

  async handleAppArmorViolation(alert) {
    logger.info('AppArmor violation detected:', alert);
  }

  async handleSeccompViolation(alert) {
    logger.info('Seccomp violation detected:', alert);
  }
}

module.exports = new ContainerSecurityService();