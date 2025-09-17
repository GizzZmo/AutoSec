/**
 * Nessus Vulnerability Scanner Integration
 * Provides integration with Tenable Nessus vulnerability scanner
 */

const axios = require('axios');
const https = require('https');
const logger = require('../config/logger');

class NessusIntegration {
  constructor(config) {
    this.config = config;
    this.baseUrl = `${config.protocol}://${config.hostname}:${config.port}`;
    this.token = null;
    this.httpClient = this.createHttpClient();
  }

  /**
   * Create HTTP client with SSL configuration
   */
  createHttpClient() {
    return axios.create({
      baseURL: this.baseUrl,
      timeout: 60000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: this.config.verifyCert
      })
    });
  }

  /**
   * Initialize the integration
   */
  async initialize() {
    try {
      logger.info('Initializing Nessus integration...');
      
      // Authenticate and get token
      await this.authenticate();
      
      // Test connectivity
      await this.healthCheck();
      
      logger.info('Nessus integration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Nessus integration:', error);
      throw error;
    }
  }

  /**
   * Authenticate with Nessus and get session token
   */
  async authenticate() {
    try {
      const authData = {
        username: this.config.username,
        password: this.config.password,
      };

      const response = await this.httpClient.post('/session', authData);
      this.token = response.data.token;
      
      // Set token in default headers
      this.httpClient.defaults.headers.common['X-Cookie'] = `token=${this.token}`;
      
      logger.info('Nessus authentication successful');
    } catch (error) {
      logger.error('Nessus authentication failed:', error);
      throw error;
    }
  }

  /**
   * Start a vulnerability scan
   */
  async startScan(scanConfig) {
    try {
      await this.ensureAuthenticated();

      // Create scan if needed
      let scanId = scanConfig.scanId;
      
      if (!scanId) {
        const createResponse = await this.httpClient.post('/scans', {
          uuid: scanConfig.policyUuid || await this.getDefaultPolicyUuid(),
          settings: {
            name: scanConfig.name || `AutoSec Scan ${Date.now()}`,
            description: scanConfig.description || 'Automated scan initiated by AutoSec',
            text_targets: Array.isArray(scanConfig.targets) ? 
              scanConfig.targets.join(',') : scanConfig.targets,
            launch_now: false,
            enabled: false,
            scanner_id: scanConfig.scannerId || 1,
            folder_id: scanConfig.folderId || this.getDefaultFolderId(),
            ...scanConfig.settings,
          }
        });
        
        scanId = createResponse.data.scan.id;
      }

      // Launch the scan
      const launchResponse = await this.httpClient.post(`/scans/${scanId}/launch`);
      
      logger.info(`Nessus scan ${scanId} started successfully`);
      return {
        success: true,
        scanId: scanId,
        scanUuid: launchResponse.data.scan_uuid,
        status: 'running',
        message: 'Scan started successfully'
      };
    } catch (error) {
      logger.error('Failed to start Nessus scan:', error);
      throw error;
    }
  }

  /**
   * Get scan status
   */
  async getScanStatus(scanId) {
    try {
      await this.ensureAuthenticated();

      if (scanId) {
        const response = await this.httpClient.get(`/scans/${scanId}`);
        const scan = response.data;
        
        return {
          scanId: scanId,
          status: scan.info.status,
          progress: scan.info.scan_progress_current || 0,
          totalProgress: scan.info.scan_progress_total || 100,
          startTime: scan.info.scan_start ? new Date(scan.info.scan_start * 1000) : null,
          endTime: scan.info.scan_end ? new Date(scan.info.scan_end * 1000) : null,
          targets: scan.info.targets,
          hostCount: scan.info.hostcount || 0,
          vulnerabilities: scan.vulnerabilities || [],
        };
      } else {
        // Get all scans
        const response = await this.httpClient.get('/scans');
        return {
          scans: response.data.scans || [],
          folders: response.data.folders || [],
        };
      }
    } catch (error) {
      logger.error('Failed to get Nessus scan status:', error);
      throw error;
    }
  }

  /**
   * Get scan results
   */
  async getScanResults(scanId, format = 'json') {
    try {
      await this.ensureAuthenticated();

      // Get scan details
      const scanResponse = await this.httpClient.get(`/scans/${scanId}`);
      const scan = scanResponse.data;

      if (format === 'json') {
        // Return structured JSON results
        const vulnerabilities = [];
        const hosts = scan.hosts || [];

        for (const host of hosts) {
          const hostDetailResponse = await this.httpClient.get(`/scans/${scanId}/hosts/${host.host_id}`);
          const hostDetail = hostDetailResponse.data;

          for (const vuln of hostDetail.vulnerabilities || []) {
            const vulnDetailResponse = await this.httpClient.get(
              `/scans/${scanId}/hosts/${host.host_id}/plugins/${vuln.plugin_id}`
            );
            const vulnDetail = vulnDetailResponse.data;

            vulnerabilities.push({
              host: host.hostname,
              host_id: host.host_id,
              plugin_id: vuln.plugin_id,
              plugin_name: vuln.plugin_name,
              plugin_family: vuln.plugin_family,
              severity: this.mapNessusSeverity(vuln.severity),
              count: vuln.count,
              vulnerability_state: vuln.vulnerability_state,
              details: vulnDetail.info || {},
              outputs: vulnDetail.outputs || [],
              ports: vulnDetail.outputs?.map(o => o.ports).flat() || [],
            });
          }
        }

        return {
          scanId: scanId,
          scanName: scan.info.name,
          status: scan.info.status,
          startTime: scan.info.scan_start ? new Date(scan.info.scan_start * 1000) : null,
          endTime: scan.info.scan_end ? new Date(scan.info.scan_end * 1000) : null,
          targets: scan.info.targets,
          hostCount: scan.info.hostcount || 0,
          vulnerabilities: vulnerabilities,
          summary: {
            total: vulnerabilities.length,
            critical: vulnerabilities.filter(v => v.severity === 'critical').length,
            high: vulnerabilities.filter(v => v.severity === 'high').length,
            medium: vulnerabilities.filter(v => v.severity === 'medium').length,
            low: vulnerabilities.filter(v => v.severity === 'low').length,
            info: vulnerabilities.filter(v => v.severity === 'info').length,
          }
        };
      } else {
        // Export in specified format (PDF, CSV, etc.)
        return await this.exportScan(scanId, format);
      }
    } catch (error) {
      logger.error('Failed to get Nessus scan results:', error);
      throw error;
    }
  }

  /**
   * Stop a running scan
   */
  async stopScan(scanId) {
    try {
      await this.ensureAuthenticated();

      await this.httpClient.post(`/scans/${scanId}/stop`);
      
      logger.info(`Nessus scan ${scanId} stopped successfully`);
      return {
        success: true,
        scanId: scanId,
        message: 'Scan stopped successfully'
      };
    } catch (error) {
      logger.error('Failed to stop Nessus scan:', error);
      throw error;
    }
  }

  /**
   * Get scan policies
   */
  async getScanPolicies() {
    try {
      await this.ensureAuthenticated();

      const response = await this.httpClient.get('/policies');
      
      return {
        success: true,
        policies: response.data.policies || []
      };
    } catch (error) {
      logger.error('Failed to get Nessus scan policies:', error);
      throw error;
    }
  }

  /**
   * Create scan policy
   */
  async createScanPolicy(policyConfig) {
    try {
      await this.ensureAuthenticated();

      const policyData = {
        uuid: policyConfig.templateUuid || await this.getDefaultTemplateUuid(),
        settings: {
          name: policyConfig.name,
          description: policyConfig.description || '',
          ...policyConfig.settings,
        }
      };

      const response = await this.httpClient.post('/policies', policyData);
      
      logger.info(`Nessus scan policy '${policyConfig.name}' created successfully`);
      return {
        success: true,
        policyId: response.data.policy_id,
        policyUuid: response.data.policy_uuid,
      };
    } catch (error) {
      logger.error('Failed to create Nessus scan policy:', error);
      throw error;
    }
  }

  /**
   * Export scan results
   */
  async exportScan(scanId, format) {
    try {
      await this.ensureAuthenticated();

      // Request export
      const exportResponse = await this.httpClient.post(`/scans/${scanId}/export`, {
        format: format,
        chapters: 'vuln_hosts_summary;vuln_by_host;compliance_exec'
      });

      const fileId = exportResponse.data.file;
      
      // Wait for export to complete
      await this.waitForExportCompletion(scanId, fileId);

      // Download the file
      const downloadResponse = await this.httpClient.get(`/scans/${scanId}/export/${fileId}/download`, {
        responseType: 'stream'
      });

      return {
        success: true,
        fileId: fileId,
        format: format,
        data: downloadResponse.data,
        contentType: downloadResponse.headers['content-type'],
      };
    } catch (error) {
      logger.error('Failed to export Nessus scan:', error);
      throw error;
    }
  }

  /**
   * Get asset inventory
   */
  async getAssetInventory() {
    try {
      await this.ensureAuthenticated();

      const response = await this.httpClient.get('/workbenches/assets');
      
      return {
        success: true,
        assets: response.data.assets || [],
        totalAssets: response.data.total_asset_count || 0,
      };
    } catch (error) {
      logger.error('Failed to get Nessus asset inventory:', error);
      throw error;
    }
  }

  /**
   * Get vulnerability statistics
   */
  async getVulnerabilityStats() {
    try {
      await this.ensureAuthenticated();

      const response = await this.httpClient.get('/workbenches/vulnerabilities');
      
      const vulnerabilities = response.data.vulnerabilities || [];
      const stats = {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 4).length,
        high: vulnerabilities.filter(v => v.severity === 3).length,
        medium: vulnerabilities.filter(v => v.severity === 2).length,
        low: vulnerabilities.filter(v => v.severity === 1).length,
        info: vulnerabilities.filter(v => v.severity === 0).length,
      };

      return {
        success: true,
        statistics: stats,
        vulnerabilities: vulnerabilities,
      };
    } catch (error) {
      logger.error('Failed to get Nessus vulnerability stats:', error);
      throw error;
    }
  }

  /**
   * Export vulnerability data
   */
  async exportData(scanId, format) {
    return await this.exportScan(scanId, format);
  }

  /**
   * Wait for export completion
   */
  async waitForExportCompletion(scanId, fileId, maxWaitTime = 300000) { // 5 minutes
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      try {
        const response = await this.httpClient.get(`/scans/${scanId}/export/${fileId}/status`);
        
        if (response.data.status === 'ready') {
          return true;
        }

        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
      } catch (error) {
        logger.error('Error checking export status:', error);
        throw error;
      }
    }

    throw new Error('Export timed out');
  }

  /**
   * Get default policy UUID
   */
  async getDefaultPolicyUuid() {
    try {
      const response = await this.httpClient.get('/editor/policy/templates');
      const templates = response.data.templates || [];
      
      // Find basic network scan template
      const basicTemplate = templates.find(t => 
        t.name.toLowerCase().includes('basic') || 
        t.name.toLowerCase().includes('network')
      );
      
      return basicTemplate ? basicTemplate.uuid : templates[0]?.uuid;
    } catch (error) {
      logger.error('Failed to get default policy UUID:', error);
      return 'basic';
    }
  }

  /**
   * Get default template UUID
   */
  async getDefaultTemplateUuid() {
    return await this.getDefaultPolicyUuid();
  }

  /**
   * Get default folder ID
   */
  getDefaultFolderId() {
    return 3; // Default "My Scans" folder
  }

  /**
   * Map Nessus severity numbers to strings
   */
  mapNessusSeverity(severity) {
    const severityMap = {
      0: 'info',
      1: 'low',
      2: 'medium',
      3: 'high',
      4: 'critical'
    };
    return severityMap[severity] || 'unknown';
  }

  /**
   * Ensure we have a valid session
   */
  async ensureAuthenticated() {
    if (!this.token) {
      await this.authenticate();
    }
  }

  /**
   * Perform health check
   */
  async healthCheck() {
    try {
      await this.ensureAuthenticated();
      const response = await this.httpClient.get('/server/status');
      return response.status === 200 && response.data.status === 'ready';
    } catch (error) {
      logger.error('Nessus health check failed:', error);
      return false;
    }
  }

  /**
   * Get integration info
   */
  getInfo() {
    return {
      type: 'nessus',
      baseUrl: this.baseUrl,
      authenticated: !!this.token,
      status: 'connected'
    };
  }
}

module.exports = NessusIntegration;