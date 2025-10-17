/**
 * Threat Hunting Controller
 * Handles HTTP requests for threat hunting operations
 */

const { threatHuntingService } = require('../services/threatHuntingService');
const logger = require('../config/logger');

/**
 * Start a new threat hunting campaign
 */
exports.startThreatHunt = async (req, res) => {
  try {
    const huntConfig = {
      ...req.body,
      userId: req.user.id
    };

    const hunt = await threatHuntingService.startThreatHunt(huntConfig);

    res.status(201).json({
      success: true,
      message: 'Threat hunt started successfully',
      data: hunt
    });
  } catch (error) {
    logger.error('Error starting threat hunt:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to start threat hunt',
      error: error.message
    });
  }
};

/**
 * Get all threat hunts with pagination and filters
 */
exports.getThreatHunts = async (req, res) => {
  try {
    const { status, priority, template, page = 1, limit = 20 } = req.query;
    
    const filters = {};
    if (status) filters.status = status;
    if (priority) filters.priority = priority;
    if (template) filters.template = template;

    // Non-admin users can only see their own hunts
    if (req.user.role !== 'admin') {
      filters.userId = req.user.id;
    }

    const result = await threatHuntingService.getThreatHunts(
      filters,
      parseInt(page),
      parseInt(limit)
    );

    res.status(200).json({
      success: true,
      data: result.hunts,
      pagination: result.pagination
    });
  } catch (error) {
    logger.error('Error getting threat hunts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get threat hunts',
      error: error.message
    });
  }
};

/**
 * Get active threat hunts
 */
exports.getActiveHunts = async (req, res) => {
  try {
    const userId = req.user.role === 'admin' ? null : req.user.id;
    const hunts = await threatHuntingService.getActiveHunts(userId);

    res.status(200).json({
      success: true,
      data: hunts
    });
  } catch (error) {
    logger.error('Error getting active hunts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get active hunts',
      error: error.message
    });
  }
};

/**
 * Get a specific threat hunt by ID
 */
exports.getThreatHunt = async (req, res) => {
  try {
    const { huntId } = req.params;
    const hunt = await threatHuntingService.getThreatHunt(huntId);

    if (!hunt) {
      return res.status(404).json({
        success: false,
        message: 'Threat hunt not found'
      });
    }

    // Check authorization
    if (req.user.role !== 'admin' && hunt.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this hunt'
      });
    }

    res.status(200).json({
      success: true,
      data: hunt
    });
  } catch (error) {
    logger.error('Error getting threat hunt:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get threat hunt',
      error: error.message
    });
  }
};

/**
 * Stop a running threat hunt
 */
exports.stopThreatHunt = async (req, res) => {
  try {
    const { huntId } = req.params;
    
    // Get hunt to check authorization
    const hunt = await threatHuntingService.getThreatHunt(huntId);
    
    if (!hunt) {
      return res.status(404).json({
        success: false,
        message: 'Threat hunt not found'
      });
    }

    // Check authorization
    if (req.user.role !== 'admin' && hunt.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to stop this hunt'
      });
    }

    const updatedHunt = await threatHuntingService.stopThreatHunt(huntId);

    res.status(200).json({
      success: true,
      message: 'Threat hunt stopped successfully',
      data: updatedHunt
    });
  } catch (error) {
    logger.error('Error stopping threat hunt:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to stop threat hunt',
      error: error.message
    });
  }
};

/**
 * Delete a threat hunt
 */
exports.deleteThreatHunt = async (req, res) => {
  try {
    const { huntId } = req.params;
    
    // Get hunt to check authorization
    const hunt = await threatHuntingService.getThreatHunt(huntId);
    
    if (!hunt) {
      return res.status(404).json({
        success: false,
        message: 'Threat hunt not found'
      });
    }

    // Check authorization
    if (req.user.role !== 'admin' && hunt.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to delete this hunt'
      });
    }

    await threatHuntingService.deleteThreatHunt(huntId);

    res.status(200).json({
      success: true,
      message: 'Threat hunt deleted successfully'
    });
  } catch (error) {
    logger.error('Error deleting threat hunt:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete threat hunt',
      error: error.message
    });
  }
};

/**
 * Get threat hunting statistics
 */
exports.getThreatHuntingStats = async (req, res) => {
  try {
    const userId = req.user.role === 'admin' ? null : req.user.id;
    const stats = await threatHuntingService.getThreatHuntingStats(userId);

    res.status(200).json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error getting threat hunting stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get threat hunting stats',
      error: error.message
    });
  }
};

/**
 * Get available threat hunting templates
 */
exports.getThreatHuntingTemplates = async (req, res) => {
  try {
    const templates = Array.from(threatHuntingService.huntTemplates.entries()).map(([key, value]) => ({
      id: key,
      ...value
    }));

    res.status(200).json({
      success: true,
      data: templates
    });
  } catch (error) {
    logger.error('Error getting threat hunting templates:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get threat hunting templates',
      error: error.message
    });
  }
};
