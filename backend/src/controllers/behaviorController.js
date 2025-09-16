const { validationResult } = require('express-validator');
const UserBehaviorAnalyzer = require('../services/behaviorAnalysis');
const NetworkBehaviorAnalyzer = require('../services/networkBehaviorAnalysis');
const UserBehavior = require('../models/UserBehavior');
const NetworkBehavior = require('../models/NetworkBehavior');
const ThreatEvent = require('../models/ThreatEvent');
const logger = require('../config/logger');

const userBehaviorAnalyzer = new UserBehaviorAnalyzer();
const networkBehaviorAnalyzer = new NetworkBehaviorAnalyzer();

// Get user behavior profiles
exports.getUserBehaviorProfiles = async (req, res) => {
  try {
    const { page = 1, limit = 20, userId, riskScore, hasAnomalies } = req.query;
    
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const whereClause = {};

    // Apply filters
    if (userId) {
      whereClause.userId = userId;
    }

    if (riskScore) {
      whereClause['riskScores.overall'] = { $gte: parseInt(riskScore) };
    }

    if (hasAnomalies === 'true') {
      whereClause['anomalies.0'] = { $exists: true };
    }

    const { docs: profiles, totalDocs, totalPages } = await UserBehavior.paginate(
      whereClause,
      {
        page: parseInt(page),
        limit: parseInt(limit),
        sort: { lastUpdated: -1 },
      }
    );

    res.json({
      success: true,
      data: {
        profiles,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalProfiles: totalDocs,
          limit: parseInt(limit),
        },
      },
    });
  } catch (error) {
    logger.error('Get user behavior profiles error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get specific user behavior profile
exports.getUserBehaviorProfile = async (req, res) => {
  try {
    const { userId } = req.params;

    const profile = await UserBehavior.findOne({ userId })
      .sort({ lastUpdated: -1 });

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: 'User behavior profile not found',
      });
    }

    res.json({
      success: true,
      data: { profile },
    });
  } catch (error) {
    logger.error('Get user behavior profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Trigger user behavior analysis
exports.analyzeUserBehavior = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { userId, endDate } = req.body;
    const analysisEndDate = endDate ? new Date(endDate) : new Date();

    // Check if user exists (simplified check)
    // In production, verify against User model

    const profile = await userBehaviorAnalyzer.analyzeUserBehavior(userId, analysisEndDate);

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: 'No data available for analysis',
      });
    }

    logger.info(`User behavior analysis triggered for user ${userId}`, {
      userId,
      triggeredBy: req.user.id,
      endDate: analysisEndDate,
    });

    res.json({
      success: true,
      message: 'User behavior analysis completed',
      data: { profile },
    });
  } catch (error) {
    logger.error('Analyze user behavior error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get network behavior profiles
exports.getNetworkBehaviorProfiles = async (req, res) => {
  try {
    const { page = 1, limit = 20, identifier, identifierType, riskScore, hasAnomalies } = req.query;
    
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const whereClause = {};

    // Apply filters
    if (identifier) {
      whereClause.identifier = { $regex: identifier, $options: 'i' };
    }

    if (identifierType) {
      whereClause.identifierType = identifierType;
    }

    if (riskScore) {
      whereClause['riskScores.overall'] = { $gte: parseInt(riskScore) };
    }

    if (hasAnomalies === 'true') {
      whereClause['anomalies.0'] = { $exists: true };
    }

    const { docs: profiles, totalDocs, totalPages } = await NetworkBehavior.paginate(
      whereClause,
      {
        page: parseInt(page),
        limit: parseInt(limit),
        sort: { lastUpdated: -1 },
      }
    );

    res.json({
      success: true,
      data: {
        profiles,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalProfiles: totalDocs,
          limit: parseInt(limit),
        },
      },
    });
  } catch (error) {
    logger.error('Get network behavior profiles error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get specific network behavior profile
exports.getNetworkBehaviorProfile = async (req, res) => {
  try {
    const { identifier, identifierType } = req.params;

    const profile = await NetworkBehavior.findOne({ identifier, identifierType })
      .sort({ lastUpdated: -1 });

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: 'Network behavior profile not found',
      });
    }

    res.json({
      success: true,
      data: { profile },
    });
  } catch (error) {
    logger.error('Get network behavior profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Trigger network behavior analysis
exports.analyzeNetworkBehavior = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { identifier, identifierType, endDate } = req.body;
    const analysisEndDate = endDate ? new Date(endDate) : new Date();

    const profile = await networkBehaviorAnalyzer.analyzeNetworkBehavior(
      identifier, 
      identifierType, 
      analysisEndDate
    );

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: 'No data available for analysis',
      });
    }

    logger.info(`Network behavior analysis triggered for ${identifierType} ${identifier}`, {
      identifier,
      identifierType,
      triggeredBy: req.user.id,
      endDate: analysisEndDate,
    });

    res.json({
      success: true,
      message: 'Network behavior analysis completed',
      data: { profile },
    });
  } catch (error) {
    logger.error('Analyze network behavior error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get threat events
exports.getThreatEvents = async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      severity, 
      status, 
      eventType, 
      search,
      startDate,
      endDate 
    } = req.query;
    
    const whereClause = {};

    // Apply filters
    if (severity) {
      whereClause.severity = severity;
    }

    if (status) {
      whereClause.status = status;
    }

    if (eventType) {
      whereClause.eventType = eventType;
    }

    if (startDate || endDate) {
      whereClause.createdAt = {};
      if (startDate) whereClause.createdAt.$gte = new Date(startDate);
      if (endDate) whereClause.createdAt.$lte = new Date(endDate);
    }

    if (search) {
      whereClause.$text = { $search: search };
    }

    const { docs: events, totalDocs, totalPages } = await ThreatEvent.paginate(
      whereClause,
      {
        page: parseInt(page),
        limit: parseInt(limit),
        sort: { createdAt: -1 },
      }
    );

    res.json({
      success: true,
      data: {
        events,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalEvents: totalDocs,
          limit: parseInt(limit),
        },
      },
    });
  } catch (error) {
    logger.error('Get threat events error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get specific threat event
exports.getThreatEvent = async (req, res) => {
  try {
    const { eventId } = req.params;

    const event = await ThreatEvent.findOne({ eventId });

    if (!event) {
      return res.status(404).json({
        success: false,
        message: 'Threat event not found',
      });
    }

    res.json({
      success: true,
      data: { event },
    });
  } catch (error) {
    logger.error('Get threat event error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Update threat event status
exports.updateThreatEventStatus = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array(),
      });
    }

    const { eventId } = req.params;
    const { status, comment, assignedTo } = req.body;

    const event = await ThreatEvent.findOne({ eventId });

    if (!event) {
      return res.status(404).json({
        success: false,
        message: 'Threat event not found',
      });
    }

    // Update status
    event.status = status;

    // Add timeline entry
    event.timeline.push({
      timestamp: new Date(),
      action: `Status changed to ${status}`,
      userId: req.user.id,
      username: req.user.username,
      description: comment || '',
    });

    // Handle assignment
    if (assignedTo) {
      event.assignedTo = {
        userId: assignedTo,
        assignedAt: new Date(),
      };
      event.timeline.push({
        timestamp: new Date(),
        action: 'Event assigned',
        userId: req.user.id,
        username: req.user.username,
        description: `Assigned to user ${assignedTo}`,
      });
    }

    // Handle acknowledgment
    if (status === 'investigating' && !event.acknowledged.by) {
      event.acknowledged = {
        by: req.user.id,
        at: new Date(),
        comment: comment || '',
      };
    }

    // Handle resolution
    if (['resolved', 'false_positive'].includes(status)) {
      event.resolved = {
        by: req.user.id,
        at: new Date(),
        resolution: status,
        comment: comment || '',
      };
    }

    await event.save();

    logger.info(`Threat event ${eventId} status updated to ${status}`, {
      eventId,
      status,
      updatedBy: req.user.id,
    });

    res.json({
      success: true,
      message: 'Threat event updated successfully',
      data: { event },
    });
  } catch (error) {
    logger.error('Update threat event error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Get behavioral analysis statistics
exports.getBehavioralAnalysisStats = async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    
    // Calculate date range
    const periodDays = parseInt(period.replace('d', ''));
    const startDate = new Date(Date.now() - (periodDays * 24 * 60 * 60 * 1000));

    // User behavior statistics
    const totalUserProfiles = await UserBehavior.countDocuments();
    const recentUserProfiles = await UserBehavior.countDocuments({
      lastUpdated: { $gte: startDate },
    });
    const highRiskUsers = await UserBehavior.countDocuments({
      'riskScores.overall': { $gte: 70 },
    });

    // Network behavior statistics
    const totalNetworkProfiles = await NetworkBehavior.countDocuments();
    const recentNetworkProfiles = await NetworkBehavior.countDocuments({
      lastUpdated: { $gte: startDate },
    });
    const highRiskNetworks = await NetworkBehavior.countDocuments({
      'riskScores.overall': { $gte: 70 },
    });

    // Threat event statistics
    const totalThreatEvents = await ThreatEvent.countDocuments();
    const recentThreatEvents = await ThreatEvent.countDocuments({
      createdAt: { $gte: startDate },
    });
    const openThreatEvents = await ThreatEvent.countDocuments({
      status: { $in: ['new', 'investigating'] },
    });

    // Anomaly statistics
    const userAnomalies = await UserBehavior.aggregate([
      { $unwind: '$anomalies' },
      { $group: { _id: '$anomalies.severity', count: { $sum: 1 } } },
    ]);

    const networkAnomalies = await NetworkBehavior.aggregate([
      { $unwind: '$anomalies' },
      { $group: { _id: '$anomalies.severity', count: { $sum: 1 } } },
    ]);

    res.json({
      success: true,
      data: {
        period: `${periodDays} days`,
        userBehavior: {
          totalProfiles: totalUserProfiles,
          recentProfiles: recentUserProfiles,
          highRiskUsers,
        },
        networkBehavior: {
          totalProfiles: totalNetworkProfiles,
          recentProfiles: recentNetworkProfiles,
          highRiskNetworks,
        },
        threatEvents: {
          total: totalThreatEvents,
          recent: recentThreatEvents,
          open: openThreatEvents,
        },
        anomalies: {
          user: userAnomalies.reduce((acc, curr) => {
            acc[curr._id] = curr.count;
            return acc;
          }, {}),
          network: networkAnomalies.reduce((acc, curr) => {
            acc[curr._id] = curr.count;
            return acc;
          }, {}),
        },
      },
    });
  } catch (error) {
    logger.error('Get behavioral analysis stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

// Bulk analyze users (admin function)
exports.bulkAnalyzeUsers = async (req, res) => {
  try {
    const { userIds, endDate } = req.body;
    const analysisEndDate = endDate ? new Date(endDate) : new Date();

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'userIds array is required',
      });
    }

    const results = [];
    const errors = [];

    for (const userId of userIds) {
      try {
        const profile = await userBehaviorAnalyzer.analyzeUserBehavior(userId, analysisEndDate);
        if (profile) {
          results.push({ userId, status: 'success', profileId: profile.id });
        } else {
          results.push({ userId, status: 'no_data' });
        }
      } catch (error) {
        logger.error(`Error analyzing user ${userId}:`, error);
        errors.push({ userId, error: error.message });
        results.push({ userId, status: 'error' });
      }
    }

    logger.info(`Bulk user analysis completed`, {
      totalUsers: userIds.length,
      successful: results.filter(r => r.status === 'success').length,
      errors: errors.length,
      triggeredBy: req.user.id,
    });

    res.json({
      success: true,
      message: `Analyzed ${userIds.length} users`,
      data: {
        results,
        summary: {
          total: userIds.length,
          successful: results.filter(r => r.status === 'success').length,
          noData: results.filter(r => r.status === 'no_data').length,
          errors: errors.length,
        },
        errors: errors.length > 0 ? errors : undefined,
      },
    });
  } catch (error) {
    logger.error('Bulk analyze users error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

module.exports = exports;