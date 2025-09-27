/**
 * Report Generation Service
 * Provides custom report generation with scheduling and delivery
 */

const cron = require('node-cron');
const logger = require('../config/logger');
const path = require('path');
const fs = require('fs').promises;

class ReportGenerationService {
  constructor() {
    this.reportTypes = new Map([
      ['security_summary', {
        name: 'Security Summary Report',
        description: 'Comprehensive security overview and threat analysis',
        defaultParams: { timeRange: '7d', includeCharts: true, format: 'pdf' },
        maxTimeRange: '365d'
      }],
      ['executive_dashboard', {
        name: 'Executive Dashboard Report',
        description: 'High-level KPIs and executive summary',
        defaultParams: { timeRange: '30d', includeKPIs: true, format: 'pdf' },
        maxTimeRange: '365d'
      }],
      ['compliance_audit', {
        name: 'Compliance Audit Report',
        description: 'Detailed compliance status and audit trail',
        defaultParams: { frameworks: ['sox', 'pci'], includeEvidence: true, format: 'pdf' },
        maxTimeRange: '90d'
      }],
      ['threat_intelligence', {
        name: 'Threat Intelligence Report',
        description: 'Latest threat intelligence and IOC analysis',
        defaultParams: { timeRange: '24h', includeTrends: true, format: 'pdf' },
        maxTimeRange: '30d'
      }],
      ['incident_response', {
        name: 'Incident Response Report',
        description: 'Detailed incident analysis and response actions',
        defaultParams: { severity: 'high', includeTimeline: true, format: 'pdf' },
        maxTimeRange: '90d'
      }],
      ['ml_performance', {
        name: 'ML Model Performance Report',
        description: 'Machine learning model accuracy and performance metrics',
        defaultParams: { models: 'all', includeMetrics: true, format: 'pdf' },
        maxTimeRange: '30d'
      }],
      ['network_analysis', {
        name: 'Network Analysis Report',
        description: 'Network behavior analysis and anomaly detection',
        defaultParams: { timeRange: '7d', includeTopology: true, format: 'pdf' },
        maxTimeRange: '30d'
      }],
      ['user_behavior', {
        name: 'User Behavior Analysis Report',
        description: 'User activity patterns and behavioral analysis',
        defaultParams: { timeRange: '30d', includeRiskScores: true, format: 'pdf' },
        maxTimeRange: '90d'
      }]
    ]);

    this.scheduledReports = new Map();
    this.initializeScheduler();
  }

  /**
   * Get available report types
   */
  getAvailableReportTypes() {
    return Array.from(this.reportTypes.entries()).map(([type, config]) => ({
      type,
      ...config
    }));
  }

  /**
   * Generate a report
   */
  async generateReport(reportType, parameters, userId) {
    try {
      if (!this.reportTypes.has(reportType)) {
        throw new Error(`Unsupported report type: ${reportType}`);
      }

      const reportConfig = this.reportTypes.get(reportType);
      const finalParams = { ...reportConfig.defaultParams, ...parameters };
      
      // Validate parameters
      await this.validateReportParameters(reportType, finalParams);

      logger.info(`Generating ${reportType} report for user ${userId}`);

      const reportData = await this.collectReportData(reportType, finalParams);
      const reportContent = await this.generateReportContent(reportType, reportData, finalParams);
      
      const Report = require('../models/Report');
      const report = new Report({
        type: reportType,
        title: this.generateReportTitle(reportType, finalParams),
        description: reportConfig.description,
        userId,
        parameters: finalParams,
        status: 'completed',
        content: reportContent,
        format: finalParams.format,
        metadata: {
          generatedAt: new Date(),
          dataPoints: reportData.totalDataPoints || 0,
          executionTime: Date.now() - (reportData.startTime || Date.now())
        }
      });

      await report.save();
      
      // Handle delivery if specified
      if (finalParams.delivery) {
        await this.deliverReport(report, finalParams.delivery);
      }

      logger.info(`Report generated successfully: ${report._id}`);
      return report;

    } catch (error) {
      logger.error(`Error generating ${reportType} report:`, error);
      
      // Save failed report record
      try {
        const Report = require('../models/Report');
        await new Report({
          type: reportType,
          title: this.generateReportTitle(reportType, parameters),
          userId,
          parameters,
          status: 'failed',
          error: error.message
        }).save();
      } catch (saveError) {
        logger.error('Error saving failed report record:', saveError);
      }
      
      throw error;
    }
  }

  /**
   * Schedule a report
   */
  async scheduleReport(reportType, parameters, schedule, userId) {
    try {
      const scheduleId = `${reportType}_${userId}_${Date.now()}`;
      
      // Validate cron expression
      if (!cron.validate(schedule.cron)) {
        throw new Error('Invalid cron expression');
      }

      const ScheduledReport = require('../models/ScheduledReport');
      const scheduledReport = new ScheduledReport({
        scheduleId,
        type: reportType,
        userId,
        parameters,
        schedule: {
          cron: schedule.cron,
          timezone: schedule.timezone || 'UTC',
          enabled: true
        },
        delivery: schedule.delivery || {},
        metadata: {
          createdAt: new Date(),
          nextRun: this.getNextRunTime(schedule.cron)
        }
      });

      await scheduledReport.save();

      // Create cron job
      const task = cron.schedule(schedule.cron, async () => {
        try {
          logger.info(`Running scheduled report: ${scheduleId}`);
          await this.generateReport(reportType, parameters, userId);
          
          // Update next run time
          scheduledReport.metadata.lastRun = new Date();
          scheduledReport.metadata.nextRun = this.getNextRunTime(schedule.cron);
          scheduledReport.metadata.runCount = (scheduledReport.metadata.runCount || 0) + 1;
          await scheduledReport.save();
          
        } catch (error) {
          logger.error(`Error in scheduled report ${scheduleId}:`, error);
          
          // Update error information
          scheduledReport.metadata.lastError = error.message;
          scheduledReport.metadata.errorCount = (scheduledReport.metadata.errorCount || 0) + 1;
          await scheduledReport.save();
        }
      }, {
        scheduled: false,
        timezone: schedule.timezone || 'UTC'
      });

      this.scheduledReports.set(scheduleId, task);
      task.start();

      logger.info(`Report scheduled: ${scheduleId}`);
      return scheduledReport;

    } catch (error) {
      logger.error('Error scheduling report:', error);
      throw error;
    }
  }

  /**
   * Collect data for report generation
   */
  async collectReportData(reportType, parameters) {
    const startTime = Date.now();
    const collectors = {
      security_summary: () => this.collectSecuritySummaryData(parameters),
      executive_dashboard: () => this.collectExecutiveDashboardData(parameters),
      compliance_audit: () => this.collectComplianceAuditData(parameters),
      threat_intelligence: () => this.collectThreatIntelligenceData(parameters),
      incident_response: () => this.collectIncidentResponseData(parameters),
      ml_performance: () => this.collectMLPerformanceData(parameters),
      network_analysis: () => this.collectNetworkAnalysisData(parameters),
      user_behavior: () => this.collectUserBehaviorData(parameters)
    };

    const collector = collectors[reportType];
    if (!collector) {
      throw new Error(`No data collector for report type: ${reportType}`);
    }

    const data = await collector();
    data.startTime = startTime;
    return data;
  }

  /**
   * Collect security summary data
   */
  async collectSecuritySummaryData(parameters) {
    const Log = require('../models/Log');
    const SecurityEvent = require('../models/SecurityEvent');
    const IOC = require('../models/IOC');
    
    const timeFilter = this.getTimeFilter(parameters.timeRange);
    
    const [
      threatStats,
      blockedIPs,
      securityEvents,
      activeIOCs,
      topThreats,
      geographicDistribution
    ] = await Promise.all([
      Log.aggregate([
        { $match: { action: 'DENY', timestamp: timeFilter } },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            uniqueIPs: { $addToSet: '$srcIp' },
            protocols: { $addToSet: '$protocol' }
          }
        }
      ]),
      Log.distinct('srcIp', { action: 'DENY', timestamp: timeFilter }),
      SecurityEvent.aggregate([
        { $match: { timestamp: timeFilter } },
        {
          $group: {
            _id: '$severity',
            count: { $sum: 1 }
          }
        }
      ]),
      IOC.countDocuments({ status: 'active' }),
      Log.aggregate([
        { $match: { action: 'DENY', timestamp: timeFilter } },
        {
          $group: {
            _id: '$srcIp',
            count: { $sum: 1 }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]),
      this.getGeographicThreatDistribution(timeFilter)
    ]);

    return {
      summary: {
        totalThreats: threatStats[0]?.total || 0,
        uniqueThreats: threatStats[0]?.uniqueIPs?.length || 0,
        protocolsInvolved: threatStats[0]?.protocols?.length || 0,
        activeIOCs,
        timeRange: parameters.timeRange
      },
      threatsBySeverity: securityEvents.reduce((acc, event) => {
        acc[event._id] = event.count;
        return acc;
      }, {}),
      topThreatSources: topThreats,
      geographicDistribution,
      totalDataPoints: (threatStats[0]?.total || 0) + securityEvents.length
    };
  }

  /**
   * Collect executive dashboard data
   */
  async collectExecutiveDashboardData(parameters) {
    const timeFilter = this.getTimeFilter(parameters.timeRange);
    
    // Executive KPIs
    const kpis = await this.calculateExecutiveKPIs(timeFilter);
    
    // Compliance scores
    const complianceScores = await this.getComplianceScores();
    
    // Risk trends
    const riskTrends = await this.getRiskTrends(timeFilter);
    
    // Budget and cost analysis
    const costAnalysis = await this.getCostAnalysis(timeFilter);

    return {
      kpis,
      complianceScores,
      riskTrends,
      costAnalysis,
      timeRange: parameters.timeRange,
      totalDataPoints: Object.keys(kpis).length + complianceScores.length
    };
  }

  /**
   * Generate report content based on type and data
   */
  async generateReportContent(reportType, data, parameters) {
    const generators = {
      security_summary: () => this.generateSecuritySummaryContent(data, parameters),
      executive_dashboard: () => this.generateExecutiveDashboardContent(data, parameters),
      compliance_audit: () => this.generateComplianceAuditContent(data, parameters),
      threat_intelligence: () => this.generateThreatIntelligenceContent(data, parameters),
      incident_response: () => this.generateIncidentResponseContent(data, parameters),
      ml_performance: () => this.generateMLPerformanceContent(data, parameters),
      network_analysis: () => this.generateNetworkAnalysisContent(data, parameters),
      user_behavior: () => this.generateUserBehaviorContent(data, parameters)
    };

    const generator = generators[reportType];
    if (!generator) {
      throw new Error(`No content generator for report type: ${reportType}`);
    }

    return await generator();
  }

  /**
   * Generate security summary report content
   */
  async generateSecuritySummaryContent(data, parameters) {
    const content = {
      sections: [
        {
          title: 'Executive Summary',
          content: `
            During the ${data.timeRange} period, AutoSec detected and blocked ${data.summary.totalThreats} threats 
            from ${data.summary.uniqueThreats} unique sources. The system processed security events across 
            ${data.summary.protocolsInvolved} different protocols and maintained ${data.summary.activeIOCs} 
            active Indicators of Compromise (IOCs).
          `
        },
        {
          title: 'Threat Analysis',
          content: data.topThreatSources,
          type: 'table',
          headers: ['Source IP', 'Threat Count', 'Risk Level']
        },
        {
          title: 'Geographic Distribution',
          content: data.geographicDistribution,
          type: 'chart',
          chartType: 'map'
        },
        {
          title: 'Severity Breakdown',
          content: data.threatsBySeverity,
          type: 'chart',
          chartType: 'pie'
        }
      ],
      metadata: {
        generatedAt: new Date(),
        dataPoints: data.totalDataPoints,
        coverage: data.timeRange
      }
    };

    if (parameters.format === 'pdf') {
      return await this.generatePDFContent(content);
    } else if (parameters.format === 'excel') {
      return await this.generateExcelContent(content);
    } else {
      return content;
    }
  }

  /**
   * Validate report parameters
   */
  async validateReportParameters(reportType, parameters) {
    const reportConfig = this.reportTypes.get(reportType);
    
    // Validate time range
    if (parameters.timeRange && !this.isValidTimeRange(parameters.timeRange, reportConfig.maxTimeRange)) {
      throw new Error(`Invalid time range. Maximum allowed: ${reportConfig.maxTimeRange}`);
    }

    // Validate format
    const allowedFormats = ['pdf', 'excel', 'json', 'csv'];
    if (parameters.format && !allowedFormats.includes(parameters.format)) {
      throw new Error(`Invalid format. Allowed: ${allowedFormats.join(', ')}`);
    }

    return true;
  }

  /**
   * Helper methods
   */
  getTimeFilter(timeRange) {
    const now = new Date();
    const ranges = {
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000,
      '90d': 90 * 24 * 60 * 60 * 1000,
      '365d': 365 * 24 * 60 * 60 * 1000
    };

    const range = ranges[timeRange] || ranges['7d'];
    return { $gte: new Date(now.getTime() - range) };
  }

  generateReportTitle(reportType, parameters) {
    const reportConfig = this.reportTypes.get(reportType);
    const timeRange = parameters.timeRange || '7d';
    const timestamp = new Date().toISOString().split('T')[0];
    
    return `${reportConfig.name} - ${timeRange} - ${timestamp}`;
  }

  isValidTimeRange(timeRange, maxTimeRange) {
    const ranges = {
      '1h': 1, '6h': 6, '24h': 24,
      '7d': 7 * 24, '30d': 30 * 24, '90d': 90 * 24, '365d': 365 * 24
    };
    
    const requestedHours = ranges[timeRange];
    const maxHours = ranges[maxTimeRange];
    
    return requestedHours && maxHours && requestedHours <= maxHours;
  }

  getNextRunTime(cronExpression) {
    // Simplified next run calculation - in production, use a proper cron parser
    return new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
  }

  initializeScheduler() {
    logger.info('Report generation scheduler initialized');
    // Load existing scheduled reports from database on startup
    this.loadScheduledReports();
  }

  async loadScheduledReports() {
    try {
      const ScheduledReport = require('../models/ScheduledReport');
      const scheduledReports = await ScheduledReport.find({ 'schedule.enabled': true });
      
      for (const report of scheduledReports) {
        await this.scheduleReport(
          report.type,
          report.parameters,
          report.schedule,
          report.userId
        );
      }
      
      logger.info(`Loaded ${scheduledReports.length} scheduled reports`);
    } catch (error) {
      logger.error('Error loading scheduled reports:', error);
    }
  }

  // Placeholder methods for other data collectors and content generators
  async collectExecutiveDashboardData(parameters) { return { kpis: {}, totalDataPoints: 0 }; }
  async collectComplianceAuditData(parameters) { return { compliance: {}, totalDataPoints: 0 }; }
  async collectThreatIntelligenceData(parameters) { return { intelligence: [], totalDataPoints: 0 }; }
  async collectIncidentResponseData(parameters) { return { incidents: [], totalDataPoints: 0 }; }
  async collectMLPerformanceData(parameters) { return { models: [], totalDataPoints: 0 }; }
  async collectNetworkAnalysisData(parameters) { return { network: {}, totalDataPoints: 0 }; }
  async collectUserBehaviorData(parameters) { return { users: [], totalDataPoints: 0 }; }

  async generateExecutiveDashboardContent(data, parameters) { return { sections: [] }; }
  async generateComplianceAuditContent(data, parameters) { return { sections: [] }; }
  async generateThreatIntelligenceContent(data, parameters) { return { sections: [] }; }
  async generateIncidentResponseContent(data, parameters) { return { sections: [] }; }
  async generateMLPerformanceContent(data, parameters) { return { sections: [] }; }
  async generateNetworkAnalysisContent(data, parameters) { return { sections: [] }; }
  async generateUserBehaviorContent(data, parameters) { return { sections: [] }; }

  async generatePDFContent(content) { return { format: 'pdf', content }; }
  async generateExcelContent(content) { return { format: 'excel', content }; }

  async getGeographicThreatDistribution(timeFilter) { return []; }
  async calculateExecutiveKPIs(timeFilter) { return {}; }
  async getComplianceScores() { return []; }
  async getRiskTrends(timeFilter) { return []; }
  async getCostAnalysis(timeFilter) { return {}; }
  async deliverReport(report, delivery) { return true; }
}

module.exports = new ReportGenerationService();