/**
 * Dashboard Customization Service
 * Provides advanced dashboard customization and widget management
 */

const mongoose = require('mongoose');
const logger = require('../config/logger');

class DashboardCustomizationService {
  constructor() {
    this.supportedWidgets = new Map([
      ['threat_summary', {
        name: 'Threat Summary',
        description: 'Overview of current threats and security status',
        defaultConfig: { timeRange: '24h', showTrends: true },
        minSize: { w: 4, h: 3 },
        maxSize: { w: 12, h: 8 }
      }],
      ['geographic_threats', {
        name: 'Geographic Threat Map',
        description: 'World map showing threat distribution',
        defaultConfig: { showBlocked: true, heatmapMode: true },
        minSize: { w: 6, h: 4 },
        maxSize: { w: 12, h: 8 }
      }],
      ['recent_events', {
        name: 'Recent Security Events',
        description: 'Timeline of recent security events',
        defaultConfig: { limit: 50, severity: 'all' },
        minSize: { w: 6, h: 4 },
        maxSize: { w: 12, h: 12 }
      }],
      ['network_topology', {
        name: '3D Network Topology',
        description: 'Interactive 3D visualization of network structure',
        defaultConfig: { showTraffic: true, nodeLabels: true },
        minSize: { w: 8, h: 6 },
        maxSize: { w: 12, h: 10 }
      }],
      ['ml_model_performance', {
        name: 'ML Model Performance',
        description: 'Machine learning model accuracy and performance metrics',
        defaultConfig: { models: 'all', timeRange: '7d' },
        minSize: { w: 6, h: 4 },
        maxSize: { w: 12, h: 8 }
      }],
      ['executive_summary', {
        name: 'Executive Summary',
        description: 'High-level KPIs and executive metrics',
        defaultConfig: { kpis: ['threats_blocked', 'uptime', 'false_positives'], period: 'monthly' },
        minSize: { w: 8, h: 4 },
        maxSize: { w: 12, h: 6 }
      }],
      ['real_time_alerts', {
        name: 'Real-time Alerts',
        description: 'Live feed of security alerts and notifications',
        defaultConfig: { autoRefresh: 5, maxAlerts: 20 },
        minSize: { w: 4, h: 4 },
        maxSize: { w: 8, h: 12 }
      }],
      ['compliance_status', {
        name: 'Compliance Status',
        description: 'Compliance framework status and audit information',
        defaultConfig: { frameworks: ['sox', 'pci', 'hipaa'], showDetails: true },
        minSize: { w: 6, h: 4 },
        maxSize: { w: 12, h: 8 }
      }],
      ['threat_intelligence', {
        name: 'Threat Intelligence Feed',
        description: 'Latest threat intelligence and IOCs',
        defaultConfig: { sources: 'all', confidence: 'high' },
        minSize: { w: 6, h: 4 },
        maxSize: { w: 12, h: 10 }
      }],
      ['network_traffic_3d', {
        name: '3D Network Traffic Visualization',
        description: 'Real-time 3D visualization of network traffic flows',
        defaultConfig: { showPackets: true, colorByProtocol: true, animationSpeed: 1.0 },
        minSize: { w: 8, h: 6 },
        maxSize: { w: 12, h: 10 }
      }]
    ]);
  }

  /**
   * Get available widget types
   */
  getAvailableWidgets() {
    return Array.from(this.supportedWidgets.entries()).map(([type, config]) => ({
      type,
      ...config
    }));
  }

  /**
   * Create a custom dashboard
   */
  async createDashboard(userId, dashboardData) {
    try {
      const Dashboard = require('../models/Dashboard');
      
      // Validate widgets
      const validatedWidgets = await this.validateWidgets(dashboardData.widgets);
      
      const dashboard = new Dashboard({
        name: dashboardData.name,
        description: dashboardData.description,
        userId,
        widgets: validatedWidgets,
        layout: dashboardData.layout || 'grid',
        theme: dashboardData.theme || 'dark',
        autoRefresh: dashboardData.autoRefresh || 30,
        isPublic: dashboardData.isPublic || false,
        tags: dashboardData.tags || [],
        metadata: {
          createdBy: userId,
          lastModifiedBy: userId,
          version: 1
        }
      });

      await dashboard.save();
      logger.info(`Dashboard created: ${dashboard._id} by user ${userId}`);
      
      return dashboard;
    } catch (error) {
      logger.error('Error creating dashboard:', error);
      throw error;
    }
  }

  /**
   * Update dashboard configuration
   */
  async updateDashboard(dashboardId, userId, updates) {
    try {
      const Dashboard = require('../models/Dashboard');
      
      const dashboard = await Dashboard.findById(dashboardId);
      if (!dashboard) {
        throw new Error('Dashboard not found');
      }

      // Check permissions
      if (dashboard.userId.toString() !== userId && !dashboard.isPublic) {
        throw new Error('Access denied');
      }

      // Validate widgets if being updated
      if (updates.widgets) {
        updates.widgets = await this.validateWidgets(updates.widgets);
      }

      // Update metadata
      updates.metadata = {
        ...dashboard.metadata,
        lastModifiedBy: userId,
        lastModified: new Date(),
        version: dashboard.metadata.version + 1
      };

      const updatedDashboard = await Dashboard.findByIdAndUpdate(
        dashboardId,
        { $set: updates },
        { new: true, runValidators: true }
      );

      logger.info(`Dashboard updated: ${dashboardId} by user ${userId}`);
      return updatedDashboard;
    } catch (error) {
      logger.error('Error updating dashboard:', error);
      throw error;
    }
  }

  /**
   * Validate widget configurations
   */
  async validateWidgets(widgets) {
    const validatedWidgets = [];

    for (const widget of widgets) {
      const widgetType = this.supportedWidgets.get(widget.type);
      if (!widgetType) {
        throw new Error(`Unsupported widget type: ${widget.type}`);
      }

      // Validate size constraints
      const { w, h } = widget.position;
      if (w < widgetType.minSize.w || h < widgetType.minSize.h) {
        throw new Error(`Widget ${widget.type} is too small. Minimum size: ${widgetType.minSize.w}x${widgetType.minSize.h}`);
      }
      if (w > widgetType.maxSize.w || h > widgetType.maxSize.h) {
        throw new Error(`Widget ${widget.type} is too large. Maximum size: ${widgetType.maxSize.w}x${widgetType.maxSize.h}`);
      }

      // Merge with default configuration
      const validatedWidget = {
        ...widget,
        config: {
          ...widgetType.defaultConfig,
          ...widget.config
        }
      };

      validatedWidgets.push(validatedWidget);
    }

    return validatedWidgets;
  }

  /**
   * Get dashboard data for rendering
   */
  async getDashboardData(dashboardId, userId, timeRange = '24h') {
    try {
      const Dashboard = require('../models/Dashboard');
      
      const dashboard = await Dashboard.findById(dashboardId);
      if (!dashboard) {
        throw new Error('Dashboard not found');
      }

      // Check permissions
      if (dashboard.userId.toString() !== userId && !dashboard.isPublic) {
        throw new Error('Access denied');
      }

      const widgetData = await Promise.all(
        dashboard.widgets.map(widget => this.getWidgetData(widget, timeRange))
      );

      return {
        dashboard: dashboard.toObject(),
        widgets: widgetData
      };
    } catch (error) {
      logger.error('Error getting dashboard data:', error);
      throw error;
    }
  }

  /**
   * Get data for a specific widget
   */
  async getWidgetData(widget, timeRange) {
    const widgetHandlers = {
      threat_summary: () => this.getThreatSummaryData(widget.config, timeRange),
      geographic_threats: () => this.getGeographicThreatData(widget.config, timeRange),
      recent_events: () => this.getRecentEventsData(widget.config, timeRange),
      network_topology: () => this.getNetworkTopologyData(widget.config),
      ml_model_performance: () => this.getMLModelPerformanceData(widget.config, timeRange),
      executive_summary: () => this.getExecutiveSummaryData(widget.config, timeRange),
      real_time_alerts: () => this.getRealTimeAlertsData(widget.config),
      compliance_status: () => this.getComplianceStatusData(widget.config),
      threat_intelligence: () => this.getThreatIntelligenceData(widget.config),
      network_traffic_3d: () => this.getNetworkTraffic3DData(widget.config, timeRange)
    };

    const handler = widgetHandlers[widget.type];
    if (!handler) {
      throw new Error(`No data handler for widget type: ${widget.type}`);
    }

    try {
      const data = await handler();
      return {
        id: widget.id,
        type: widget.type,
        position: widget.position,
        config: widget.config,
        data,
        lastUpdated: new Date()
      };
    } catch (error) {
      logger.error(`Error getting data for widget ${widget.type}:`, error);
      return {
        id: widget.id,
        type: widget.type,
        position: widget.position,
        config: widget.config,
        error: error.message,
        lastUpdated: new Date()
      };
    }
  }

  /**
   * Get threat summary data
   */
  async getThreatSummaryData(config, timeRange) {
    const Log = require('../models/Log');
    const SecurityEvent = require('../models/SecurityEvent');
    
    const timeFilter = this.getTimeFilter(timeRange);
    
    const [threatCount, blockedIPs, securityEvents] = await Promise.all([
      Log.countDocuments({
        action: 'DENY',
        timestamp: timeFilter
      }),
      Log.distinct('srcIp', {
        action: 'DENY',
        timestamp: timeFilter
      }),
      SecurityEvent.countDocuments({
        timestamp: timeFilter,
        severity: { $in: ['high', 'critical'] }
      })
    ]);

    return {
      threatsBlocked: threatCount,
      uniqueBlockedIPs: blockedIPs.length,
      highSeverityEvents: securityEvents,
      timeRange,
      trends: config.showTrends ? await this.getThreatTrends(timeRange) : null
    };
  }

  /**
   * Get geographic threat distribution data
   */
  async getGeographicThreatData(config, timeRange) {
    const Log = require('../models/Log');
    const geoIpService = require('./geoIpService');
    
    const timeFilter = this.getTimeFilter(timeRange);
    
    const threats = await Log.find({
      action: 'DENY',
      timestamp: timeFilter
    }).select('srcIp').lean();

    const geoData = new Map();
    
    for (const threat of threats) {
      const location = geoIpService.lookup(threat.srcIp);
      if (location && location.country) {
        const country = location.country;
        geoData.set(country, (geoData.get(country) || 0) + 1);
      }
    }

    const result = Array.from(geoData.entries()).map(([country, count]) => ({
      country,
      count,
      intensity: count / Math.max(...geoData.values())
    }));

    return {
      threatsByCountry: result,
      totalThreats: threats.length,
      timeRange,
      heatmapMode: config.heatmapMode
    };
  }

  /**
   * Get 3D network traffic visualization data
   */
  async getNetworkTraffic3DData(config, timeRange) {
    const NetworkBehavior = require('../models/NetworkBehavior');
    
    const timeFilter = this.getTimeFilter(timeRange);
    
    const networkData = await NetworkBehavior.aggregate([
      { $match: { lastUpdated: timeFilter } },
      {
        $project: {
          identifier: 1,
          'patterns.networkConnections': 1,
          'patterns.protocolDistribution': 1,
          'riskScores.overall': 1
        }
      },
      { $limit: 1000 } // Limit for performance
    ]);

    const nodes = [];
    const edges = [];
    const nodeMap = new Map();

    networkData.forEach((item, index) => {
      const nodeId = item.identifier;
      
      if (!nodeMap.has(nodeId)) {
        nodes.push({
          id: nodeId,
          label: nodeId,
          size: Math.max(5, item.riskScores?.overall || 5),
          color: this.getRiskColor(item.riskScores?.overall || 0),
          type: 'host'
        });
        nodeMap.set(nodeId, nodes.length - 1);
      }

      // Add connections as edges
      if (item.patterns?.networkConnections) {
        item.patterns.networkConnections.forEach(connection => {
          edges.push({
            from: nodeId,
            to: connection.destination || `unknown_${Math.random()}`,
            weight: connection.count || 1,
            protocol: connection.protocol || 'unknown',
            color: this.getTrafficColor(connection.protocol)
          });
        });
      }
    });

    return {
      nodes,
      edges,
      config: {
        showPackets: config.showPackets,
        colorByProtocol: config.colorByProtocol,
        animationSpeed: config.animationSpeed
      },
      stats: {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        timeRange
      }
    };
  }

  /**
   * Get time filter based on range
   */
  getTimeFilter(timeRange) {
    const now = new Date();
    const ranges = {
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000
    };

    const range = ranges[timeRange] || ranges['24h'];
    return { $gte: new Date(now.getTime() - range) };
  }

  /**
   * Get risk-based color for nodes
   */
  getRiskColor(riskScore) {
    if (riskScore >= 80) return '#ff4444';
    if (riskScore >= 60) return '#ff8800';
    if (riskScore >= 40) return '#ffdd00';
    if (riskScore >= 20) return '#88ff00';
    return '#00ff44';
  }

  /**
   * Get protocol-based color for traffic
   */
  getTrafficColor(protocol) {
    const colors = {
      'http': '#4CAF50',
      'https': '#8BC34A',
      'ssh': '#FF9800',
      'ftp': '#FF5722',
      'smtp': '#9C27B0',
      'dns': '#2196F3',
      'tcp': '#607D8B',
      'udp': '#795548'
    };
    return colors[protocol?.toLowerCase()] || '#9E9E9E';
  }

  // Placeholder methods for other widget data handlers
  async getRecentEventsData(config, timeRange) { return { events: [], timeRange }; }
  async getNetworkTopologyData(config) { return { nodes: [], links: [] }; }
  async getMLModelPerformanceData(config, timeRange) { return { models: [], timeRange }; }
  async getExecutiveSummaryData(config, timeRange) { return { kpis: {}, timeRange }; }
  async getRealTimeAlertsData(config) { return { alerts: [] }; }
  async getComplianceStatusData(config) { return { frameworks: {} }; }
  async getThreatIntelligenceData(config) { return { feeds: [] }; }
  async getThreatTrends(timeRange) { return { trend: 'stable' }; }
}

module.exports = new DashboardCustomizationService();