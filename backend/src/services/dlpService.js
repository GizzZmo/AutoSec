/**
 * Data Loss Prevention (DLP) Service
 * Monitors and prevents unauthorized data exfiltration
 */

const logger = require('../config/logger');
const crypto = require('crypto');

class DLPService {
  constructor() {
    this.dataTypes = new Map([
      ['pii', {
        name: 'Personally Identifiable Information',
        patterns: [
          { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/, weight: 10 },
          { name: 'Email', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, weight: 5 },
          { name: 'Phone', regex: /\b\d{3}-\d{3}-\d{4}\b/, weight: 3 },
          { name: 'Credit Card', regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, weight: 10 }
        ]
      }],
      ['phi', {
        name: 'Protected Health Information',
        patterns: [
          { name: 'Medical Record Number', regex: /\bMRN[\s:]?\d{6,10}\b/i, weight: 10 },
          { name: 'Patient ID', regex: /\bPATIENT[\s_]?ID[\s:]?\d{4,8}\b/i, weight: 8 },
          { name: 'Health Plan ID', regex: /\bHPID[\s:]?\d{6,12}\b/i, weight: 7 }
        ]
      }],
      ['financial', {
        name: 'Financial Information',
        patterns: [
          { name: 'Bank Account', regex: /\b\d{8,17}\b/, weight: 9 },
          { name: 'Routing Number', regex: /\b\d{9}\b/, weight: 7 },
          { name: 'IBAN', regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/, weight: 8 }
        ]
      }],
      ['credentials', {
        name: 'Credentials and Secrets',
        patterns: [
          { name: 'API Key', regex: /\b[A-Za-z0-9]{32,}\b/, weight: 8 },
          { name: 'Password', regex: /password[\s=:]\s*[^\s]{8,}/i, weight: 9 },
          { name: 'Private Key', regex: /-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----/, weight: 10 },
          { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/, weight: 8 }
        ]
      }],
      ['proprietary', {
        name: 'Proprietary Information',
        patterns: [
          { name: 'Confidential Marker', regex: /\b(confidential|proprietary|internal use only)\b/i, weight: 6 },
          { name: 'Trade Secret', regex: /\btrade\s+secret\b/i, weight: 8 },
          { name: 'Patent Number', regex: /\bUS\d{7,8}\b/, weight: 5 }
        ]
      }]
    ]);

    this.dlpPolicies = new Map();
    this.scanResults = new Map();
    this.quarantineActions = new Set();
    
    this.initializeDefaultPolicies();
  }

  /**
   * Scan content for sensitive data
   */
  async scanContent(scanRequest) {
    try {
      const {
        content,
        contentType = 'text',
        source,
        userId,
        metadata = {}
      } = scanRequest;

      const scanId = this.generateScanId();
      logger.info(`Starting DLP scan: ${scanId}`);

      const startTime = Date.now();
      const findings = [];
      let totalSensitivityScore = 0;

      // Scan for each data type
      for (const [dataType, config] of this.dataTypes) {
        const typeFindings = await this.scanForDataType(content, dataType, config);
        findings.push(...typeFindings);
        
        // Calculate sensitivity score
        typeFindings.forEach(finding => {
          totalSensitivityScore += finding.weight * finding.occurrences;
        });
      }

      // Additional scans based on content type
      if (contentType === 'file') {
        const fileFindings = await this.scanFileMetadata(metadata);
        findings.push(...fileFindings);
      }

      // Apply contextual analysis
      const contextualFindings = await this.performContextualAnalysis(content, findings);
      findings.push(...contextualFindings);

      const results = {
        scanId,
        timestamp: new Date(),
        source,
        contentType,
        userId,
        findings,
        summary: {
          totalFindings: findings.length,
          sensitivityScore: totalSensitivityScore,
          riskLevel: this.calculateRiskLevel(totalSensitivityScore),
          dataTypesFound: [...new Set(findings.map(f => f.dataType))]
        },
        duration: Date.now() - startTime,
        metadata
      };

      // Apply DLP policies
      const policyResults = await this.applyDLPPolicies(results);
      results.policyActions = policyResults.actions;
      results.policyViolations = policyResults.violations;

      // Store scan results
      this.scanResults.set(scanId, results);
      await this.saveDLPScanResults(results);

      // Execute policy actions
      if (policyResults.actions.length > 0) {
        await this.executePolicyActions(policyResults.actions, results);
      }

      logger.info(`DLP scan completed: ${scanId} (${results.duration}ms, ${findings.length} findings)`);
      return results;

    } catch (error) {
      logger.error('Error in DLP content scan:', error);
      throw error;
    }
  }

  /**
   * Scan for specific data type patterns
   */
  async scanForDataType(content, dataType, config) {
    const findings = [];

    for (const pattern of config.patterns) {
      const matches = content.match(new RegExp(pattern.regex, 'gi'));
      
      if (matches && matches.length > 0) {
        // Extract context around matches
        const contexts = this.extractContexts(content, pattern.regex);
        
        findings.push({
          id: this.generateFindingId(),
          dataType,
          patternName: pattern.name,
          occurrences: matches.length,
          weight: pattern.weight,
          severity: this.calculateSeverity(pattern.weight, matches.length),
          matches: matches.slice(0, 5), // Limit for storage
          contexts: contexts.slice(0, 3), // Sample contexts
          confidence: this.calculateConfidence(pattern, matches)
        });
      }
    }

    return findings;
  }

  /**
   * Perform contextual analysis
   */
  async performContextualAnalysis(content, findings) {
    const contextualFindings = [];

    // Check for data proximity (multiple sensitive data types near each other)
    const proximityFindings = this.analyzeDataProximity(content, findings);
    contextualFindings.push(...proximityFindings);

    // Check for bulk data patterns
    const bulkDataFindings = this.analyzeBulkData(content, findings);
    contextualFindings.push(...bulkDataFindings);

    // Check for encoding/obfuscation attempts
    const obfuscationFindings = this.analyzeObfuscation(content);
    contextualFindings.push(...obfuscationFindings);

    return contextualFindings;
  }

  /**
   * Analyze data proximity (sensitive data appearing together)
   */
  analyzeDataProximity(content, findings) {
    const proximityFindings = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineFindings = findings.filter(f => 
        f.contexts.some(ctx => ctx.includes(line))
      );

      if (lineFindings.length >= 2) {
        const dataTypes = [...new Set(lineFindings.map(f => f.dataType))];
        
        if (dataTypes.length >= 2) {
          proximityFindings.push({
            id: this.generateFindingId(),
            type: 'proximity',
            dataType: 'contextual',
            patternName: 'Data Proximity',
            description: `Multiple sensitive data types found in proximity: ${dataTypes.join(', ')}`,
            severity: 'high',
            weight: 15,
            line: i + 1,
            context: line.substring(0, 200),
            relatedFindings: lineFindings.map(f => f.id)
          });
        }
      }
    }

    return proximityFindings;
  }

  /**
   * Analyze bulk data patterns
   */
  analyzeBulkData(content, findings) {
    const bulkFindings = [];
    
    // Count findings by data type
    const dataTypeCounts = {};
    findings.forEach(finding => {
      dataTypeCounts[finding.dataType] = (dataTypeCounts[finding.dataType] || 0) + finding.occurrences;
    });

    // Check for bulk patterns
    Object.entries(dataTypeCounts).forEach(([dataType, count]) => {
      if (count >= 10) { // Threshold for bulk data
        bulkFindings.push({
          id: this.generateFindingId(),
          type: 'bulk_data',
          dataType: 'contextual',
          patternName: 'Bulk Data Detection',
          description: `Large volume of ${dataType} data detected (${count} occurrences)`,
          severity: 'high',
          weight: 20,
          occurrences: count,
          relatedDataType: dataType
        });
      }
    });

    return bulkFindings;
  }

  /**
   * Analyze obfuscation attempts
   */
  analyzeObfuscation(content) {
    const obfuscationFindings = [];

    // Check for Base64 encoded content
    const base64Pattern = /[A-Za-z0-9+\/]{20,}={0,2}/g;
    const base64Matches = content.match(base64Pattern);
    
    if (base64Matches && base64Matches.length > 0) {
      obfuscationFindings.push({
        id: this.generateFindingId(),
        type: 'obfuscation',
        dataType: 'contextual',
        patternName: 'Base64 Encoding Detected',
        description: 'Potential Base64 encoded sensitive data',
        severity: 'medium',
        weight: 8,
        occurrences: base64Matches.length,
        samples: base64Matches.slice(0, 3)
      });
    }

    // Check for hexadecimal patterns
    const hexPattern = /[0-9a-fA-F]{32,}/g;
    const hexMatches = content.match(hexPattern);
    
    if (hexMatches && hexMatches.length > 5) {
      obfuscationFindings.push({
        id: this.generateFindingId(),
        type: 'obfuscation',
        dataType: 'contextual',
        patternName: 'Hexadecimal Data Detected',
        description: 'Large amounts of hexadecimal data detected',
        severity: 'low',
        weight: 4,
        occurrences: hexMatches.length
      });
    }

    return obfuscationFindings;
  }

  /**
   * Apply DLP policies to scan results
   */
  async applyDLPPolicies(scanResults) {
    const actions = [];
    const violations = [];

    for (const [policyName, policy] of this.dlpPolicies) {
      const policyResult = await this.evaluatePolicy(policy, scanResults);
      
      if (policyResult.violated) {
        violations.push({
          policy: policyName,
          description: policy.description,
          severity: policyResult.severity,
          triggeredBy: policyResult.triggeredBy
        });

        // Add policy actions
        actions.push(...policyResult.actions);
      }
    }

    return { actions, violations };
  }

  /**
   * Evaluate a single DLP policy
   */
  async evaluatePolicy(policy, scanResults) {
    const result = {
      violated: false,
      severity: 'low',
      actions: [],
      triggeredBy: []
    };

    // Check threshold conditions
    if (policy.conditions.sensitivityScore && 
        scanResults.summary.sensitivityScore >= policy.conditions.sensitivityScore) {
      result.violated = true;
      result.severity = 'high';
      result.triggeredBy.push('sensitivity_threshold');
    }

    if (policy.conditions.dataTypes) {
      const foundDataTypes = scanResults.summary.dataTypesFound;
      const prohibitedTypes = policy.conditions.dataTypes.filter(type => 
        foundDataTypes.includes(type)
      );
      
      if (prohibitedTypes.length > 0) {
        result.violated = true;
        result.severity = Math.max(result.severity, 'medium');
        result.triggeredBy.push(...prohibitedTypes);
      }
    }

    if (policy.conditions.totalFindings && 
        scanResults.summary.totalFindings >= policy.conditions.totalFindings) {
      result.violated = true;
      result.triggeredBy.push('findings_threshold');
    }

    // Add policy actions if violated
    if (result.violated && policy.actions) {
      result.actions = policy.actions.map(action => ({
        ...action,
        policyName: policy.name,
        scanId: scanResults.scanId
      }));
    }

    return result;
  }

  /**
   * Execute policy actions
   */
  async executePolicyActions(actions, scanResults) {
    for (const action of actions) {
      try {
        await this.executeAction(action, scanResults);
      } catch (error) {
        logger.error(`Error executing DLP action ${action.type}:`, error);
      }
    }
  }

  /**
   * Execute a single policy action
   */
  async executeAction(action, scanResults) {
    logger.info(`Executing DLP action: ${action.type}`, {
      scanId: scanResults.scanId,
      policy: action.policyName
    });

    switch (action.type) {
      case 'block':
        await this.blockContent(scanResults, action);
        break;
        
      case 'quarantine':
        await this.quarantineContent(scanResults, action);
        break;
        
      case 'encrypt':
        await this.encryptContent(scanResults, action);
        break;
        
      case 'notify':
        await this.sendNotification(scanResults, action);
        break;
        
      case 'audit_log':
        await this.logAuditEvent(scanResults, action);
        break;
        
      case 'redact':
        await this.redactSensitiveData(scanResults, action);
        break;
        
      default:
        logger.warn(`Unknown DLP action type: ${action.type}`);
    }
  }

  /**
   * Block content access/transmission
   */
  async blockContent(scanResults, action) {
    const blockRecord = {
      scanId: scanResults.scanId,
      timestamp: new Date(),
      reason: 'DLP policy violation',
      policy: action.policyName,
      source: scanResults.source,
      userId: scanResults.userId
    };

    // Add to blocked content registry
    await this.addToBlockedContent(blockRecord);
    
    logger.warn('Content blocked by DLP policy', blockRecord);
  }

  /**
   * Quarantine suspicious content
   */
  async quarantineContent(scanResults, action) {
    const quarantineId = this.generateQuarantineId();
    this.quarantineActions.add(quarantineId);

    const quarantineRecord = {
      quarantineId,
      scanId: scanResults.scanId,
      timestamp: new Date(),
      reason: action.reason || 'Sensitive data detected',
      findings: scanResults.findings.length,
      sensitivityScore: scanResults.summary.sensitivityScore,
      source: scanResults.source,
      userId: scanResults.userId,
      status: 'quarantined'
    };

    await this.addToQuarantine(quarantineRecord);
    
    logger.info('Content quarantined', quarantineRecord);
  }

  /**
   * Redact sensitive data from content
   */
  async redactSensitiveData(scanResults, action) {
    const redactionMap = new Map();

    for (const finding of scanResults.findings) {
      if (finding.matches) {
        for (const match of finding.matches) {
          const redacted = this.redactString(match, finding.patternName);
          redactionMap.set(match, redacted);
        }
      }
    }

    const redactionRecord = {
      scanId: scanResults.scanId,
      timestamp: new Date(),
      redactions: redactionMap.size,
      policy: action.policyName
    };

    await this.logRedactionEvent(redactionRecord);
    
    logger.info('Sensitive data redacted', redactionRecord);
    return redactionMap;
  }

  /**
   * Initialize default DLP policies
   */
  initializeDefaultPolicies() {
    // High sensitivity content policy
    this.dlpPolicies.set('high_sensitivity', {
      name: 'High Sensitivity Content',
      description: 'Block content with high sensitivity scores',
      conditions: {
        sensitivityScore: 50,
        dataTypes: ['pii', 'phi', 'financial']
      },
      actions: [
        { type: 'block', reason: 'High sensitivity content detected' },
        { type: 'notify', recipients: ['security@company.com'] },
        { type: 'audit_log', level: 'high' }
      ]
    });

    // Credentials leak policy
    this.dlpPolicies.set('credentials_leak', {
      name: 'Credentials Leak Prevention',
      description: 'Prevent credential exposure',
      conditions: {
        dataTypes: ['credentials']
      },
      actions: [
        { type: 'quarantine', reason: 'Credentials detected' },
        { type: 'notify', recipients: ['security@company.com'] },
        { type: 'audit_log', level: 'critical' }
      ]
    });

    // Bulk data exfiltration policy
    this.dlpPolicies.set('bulk_data', {
      name: 'Bulk Data Exfiltration',
      description: 'Detect bulk sensitive data movement',
      conditions: {
        totalFindings: 20,
        sensitivityScore: 100
      },
      actions: [
        { type: 'block', reason: 'Bulk sensitive data detected' },
        { type: 'quarantine', reason: 'Potential data exfiltration' },
        { type: 'notify', recipients: ['security@company.com', 'compliance@company.com'] }
      ]
    });

    logger.info('DLP policies initialized');
  }

  /**
   * Monitor network traffic for DLP violations
   */
  async monitorNetworkTraffic(trafficData) {
    try {
      const {
        protocol,
        sourceIp,
        destinationIp,
        payload,
        size,
        timestamp
      } = trafficData;

      // Skip if payload is too large to scan efficiently
      if (size > 10 * 1024 * 1024) { // 10MB limit
        return null;
      }

      // Decode payload if possible
      let content = '';
      try {
        content = Buffer.from(payload, 'base64').toString('utf8');
      } catch (error) {
        // If decoding fails, treat as binary data
        content = payload;
      }

      // Perform DLP scan on network content
      const scanResults = await this.scanContent({
        content,
        contentType: 'network',
        source: `${sourceIp} -> ${destinationIp}`,
        metadata: {
          protocol,
          size,
          timestamp
        }
      });

      // Additional network-specific analysis
      if (scanResults.summary.sensitivityScore > 30) {
        logger.warn('Sensitive data detected in network traffic', {
          sourceIp,
          destinationIp,
          protocol,
          sensitivityScore: scanResults.summary.sensitivityScore,
          findings: scanResults.summary.totalFindings
        });
      }

      return scanResults;

    } catch (error) {
      logger.error('Error monitoring network traffic for DLP:', error);
      return null;
    }
  }

  /**
   * Helper methods
   */
  generateScanId() {
    return `dlp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateFindingId() {
    return `finding_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateQuarantineId() {
    return `quarantine_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  extractContexts(content, regex) {
    const contexts = [];
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      if (regex.test(line)) {
        const start = Math.max(0, index - 1);
        const end = Math.min(lines.length - 1, index + 1);
        contexts.push(lines.slice(start, end + 1).join('\n'));
      }
    });

    return contexts;
  }

  calculateSeverity(weight, occurrences) {
    const score = weight * Math.log(occurrences + 1);
    if (score >= 20) return 'critical';
    if (score >= 15) return 'high';
    if (score >= 10) return 'medium';
    return 'low';
  }

  calculateConfidence(pattern, matches) {
    // Simple confidence calculation based on pattern specificity
    let confidence = 0.7; // Base confidence
    
    if (pattern.name.includes('SSN') || pattern.name.includes('Credit Card')) {
      confidence = 0.95; // High confidence for well-defined patterns
    } else if (pattern.name.includes('Email') || pattern.name.includes('Phone')) {
      confidence = 0.85;
    }

    // Adjust based on number of matches
    if (matches.length > 1) {
      confidence = Math.min(0.99, confidence + 0.1);
    }

    return Math.round(confidence * 100) / 100;
  }

  calculateRiskLevel(sensitivityScore) {
    if (sensitivityScore >= 100) return 'critical';
    if (sensitivityScore >= 50) return 'high';
    if (sensitivityScore >= 20) return 'medium';
    if (sensitivityScore >= 5) return 'low';
    return 'minimal';
  }

  redactString(text, patternName) {
    if (patternName.includes('SSN')) {
      return 'XXX-XX-' + text.slice(-4);
    } else if (patternName.includes('Credit Card')) {
      return 'XXXX-XXXX-XXXX-' + text.slice(-4);
    } else if (patternName.includes('Email')) {
      const parts = text.split('@');
      return parts[0].charAt(0) + '***@' + parts[1];
    } else {
      return 'X'.repeat(Math.min(text.length, 10));
    }
  }

  // Placeholder methods for external integrations
  async saveDLPScanResults(results) {
    // Save to database
    logger.info(`DLP scan results saved: ${results.scanId}`);
  }

  async addToBlockedContent(blockRecord) {
    // Add to blocked content registry
    logger.info(`Content blocked: ${blockRecord.scanId}`);
  }

  async addToQuarantine(quarantineRecord) {
    // Add to quarantine system
    logger.info(`Content quarantined: ${quarantineRecord.quarantineId}`);
  }

  async logRedactionEvent(redactionRecord) {
    // Log redaction event
    logger.info(`Data redacted: ${redactionRecord.scanId}`);
  }

  async logAuditEvent(scanResults, action) {
    // Log audit event
    logger.info(`DLP audit event logged: ${scanResults.scanId}`);
  }

  async sendNotification(scanResults, action) {
    // Send notification
    logger.info(`DLP notification sent for scan: ${scanResults.scanId}`);
  }

  async encryptContent(scanResults, action) {
    // Encrypt sensitive content
    logger.info(`Content encrypted: ${scanResults.scanId}`);
  }

  async scanFileMetadata(metadata) {
    // Scan file metadata for sensitive information
    return [];
  }
}

module.exports = new DLPService();