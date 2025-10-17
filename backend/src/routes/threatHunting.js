/**
 * Threat Hunting Routes
 * API endpoints for threat hunting operations
 */

const express = require('express');
const router = express.Router();
const threatHuntingController = require('../controllers/threatHuntingController');
const { authenticate, requireMinRole } = require('../middleware/auth');
const { body, query, param, validationResult } = require('express-validator');

// Validation middleware
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

// Validation rules
const startThreatHuntValidation = [
  body('name').trim().notEmpty().withMessage('Hunt name is required'),
  body('description').optional().trim(),
  body('hypothesis').optional().trim(),
  body('queries').optional().isArray().withMessage('Queries must be an array'),
  body('queries.*.name').optional().trim().notEmpty().withMessage('Query name is required'),
  body('queries.*.type').optional().isIn(['network', 'behavior', 'ioc', 'threat_event', 'custom']).withMessage('Invalid query type'),
  body('queries.*.pattern').optional().trim().notEmpty().withMessage('Query pattern is required'),
  body('queries.*.timeWindow').optional().trim(),
  body('template').optional().isIn(['apt-detection', 'data-exfiltration', 'insider-threat', 'ransomware', 'custom']).withMessage('Invalid template'),
  body('timeRange').optional().trim().matches(/^\d+[mhd]$/).withMessage('Invalid time range format (e.g., 24h, 7d)'),
  body('targets').optional().isArray().withMessage('Targets must be an array'),
  body('priority').optional().isIn(['low', 'medium', 'high', 'critical']).withMessage('Invalid priority'),
  body('automated').optional().isBoolean().withMessage('Automated must be a boolean'),
  validate
];

const getThreatHuntsValidation = [
  query('status').optional().isIn(['pending', 'running', 'completed', 'failed', 'stopped']).withMessage('Invalid status'),
  query('priority').optional().isIn(['low', 'medium', 'high', 'critical']).withMessage('Invalid priority'),
  query('template').optional().isIn(['apt-detection', 'data-exfiltration', 'insider-threat', 'ransomware', 'custom']).withMessage('Invalid template'),
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  validate
];

const huntIdValidation = [
  param('huntId').isMongoId().withMessage('Invalid hunt ID'),
  validate
];

/**
 * @swagger
 * /api/threat-hunting/start:
 *   post:
 *     summary: Start a new threat hunting campaign
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *             properties:
 *               name:
 *                 type: string
 *                 description: Name of the threat hunt
 *               description:
 *                 type: string
 *                 description: Detailed description of the hunt
 *               hypothesis:
 *                 type: string
 *                 description: Threat hypothesis being investigated
 *               queries:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     name:
 *                       type: string
 *                     type:
 *                       type: string
 *                       enum: [network, behavior, ioc, threat_event, custom]
 *                     pattern:
 *                       type: string
 *                     timeWindow:
 *                       type: string
 *               template:
 *                 type: string
 *                 enum: [apt-detection, data-exfiltration, insider-threat, ransomware, custom]
 *               timeRange:
 *                 type: string
 *                 description: Time range for hunt (e.g., 24h, 7d)
 *               priority:
 *                 type: string
 *                 enum: [low, medium, high, critical]
 *     responses:
 *       201:
 *         description: Threat hunt started successfully
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.post('/start', authenticate, requireMinRole('analyst'), startThreatHuntValidation, threatHuntingController.startThreatHunt);

/**
 * @swagger
 * /api/threat-hunting:
 *   get:
 *     summary: Get all threat hunts with pagination and filters
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [pending, running, completed, failed, stopped]
 *       - in: query
 *         name: priority
 *         schema:
 *           type: string
 *           enum: [low, medium, high, critical]
 *       - in: query
 *         name: template
 *         schema:
 *           type: string
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *     responses:
 *       200:
 *         description: List of threat hunts
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get('/', authenticate, requireMinRole('analyst'), getThreatHuntsValidation, threatHuntingController.getThreatHunts);

/**
 * @swagger
 * /api/threat-hunting/active:
 *   get:
 *     summary: Get currently active threat hunts
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of active hunts
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get('/active', authenticate, requireMinRole('analyst'), threatHuntingController.getActiveHunts);

/**
 * @swagger
 * /api/threat-hunting/stats:
 *   get:
 *     summary: Get threat hunting statistics
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Threat hunting statistics
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get('/stats', authenticate, requireMinRole('analyst'), threatHuntingController.getThreatHuntingStats);

/**
 * @swagger
 * /api/threat-hunting/templates:
 *   get:
 *     summary: Get available threat hunting templates
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of available templates
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.get('/templates', authenticate, requireMinRole('analyst'), threatHuntingController.getThreatHuntingTemplates);

/**
 * @swagger
 * /api/threat-hunting/{huntId}:
 *   get:
 *     summary: Get a specific threat hunt by ID
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: huntId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Threat hunt details
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Hunt not found
 *       500:
 *         description: Server error
 */
router.get('/:huntId', authenticate, requireMinRole('analyst'), huntIdValidation, threatHuntingController.getThreatHunt);

/**
 * @swagger
 * /api/threat-hunting/{huntId}/stop:
 *   post:
 *     summary: Stop a running threat hunt
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: huntId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Hunt stopped successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Hunt not found
 *       500:
 *         description: Server error
 */
router.post('/:huntId/stop', authenticate, requireMinRole('analyst'), huntIdValidation, threatHuntingController.stopThreatHunt);

/**
 * @swagger
 * /api/threat-hunting/{huntId}:
 *   delete:
 *     summary: Delete a threat hunt
 *     tags: [Threat Hunting]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: huntId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Hunt deleted successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Hunt not found
 *       500:
 *         description: Server error
 */
router.delete('/:huntId', authenticate, requireMinRole('analyst'), huntIdValidation, threatHuntingController.deleteThreatHunt);

module.exports = router;
