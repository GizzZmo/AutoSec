const express = require('express');
const router = express.Router();

const behaviorController = require('../controllers/behaviorController');
const { authenticate, requireMinRole } = require('../middleware/auth');
const {
  validateUserBehaviorAnalysis,
  validateNetworkBehaviorAnalysis,
  validateThreatEventStatusUpdate,
  validateBulkUserAnalysis,
  validatePagination,
  validateThreatEventFilters,
  validateBehaviorStatsQuery,
} = require('../middleware/validation');

/**
 * @swagger
 * /api/behavior/users:
 *   get:
 *     tags: [Behavioral Analysis]
 *     summary: Get user behavior profiles
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *         description: Number of profiles per page
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Filter by user ID
 *       - in: query
 *         name: riskScore
 *         schema:
 *           type: integer
 *           minimum: 0
 *           maximum: 100
 *         description: Minimum risk score filter
 *       - in: query
 *         name: hasAnomalies
 *         schema:
 *           type: boolean
 *         description: Filter profiles with anomalies
 *     responses:
 *       200:
 *         description: User behavior profiles retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/users', authenticate, requireMinRole('analyst'), validatePagination, behaviorController.getUserBehaviorProfiles);

/**
 * @swagger
 * /api/behavior/users/{userId}:
 *   get:
 *     tags: [Behavioral Analysis]
 *     summary: Get specific user behavior profile
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: User ID
 *     responses:
 *       200:
 *         description: User behavior profile retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Profile not found
 */
router.get('/users/:userId', authenticate, requireMinRole('analyst'), behaviorController.getUserBehaviorProfile);

/**
 * @swagger
 * /api/behavior/users/analyze:
 *   post:
 *     tags: [Behavioral Analysis]
 *     summary: Trigger user behavior analysis
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *             properties:
 *               userId:
 *                 type: string
 *                 format: uuid
 *               endDate:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       200:
 *         description: User behavior analysis completed
 *       400:
 *         description: Validation errors
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: No data available for analysis
 */
router.post('/users/analyze', authenticate, requireMinRole('analyst'), validateUserBehaviorAnalysis, behaviorController.analyzeUserBehavior);

/**
 * @swagger
 * /api/behavior/users/bulk-analyze:
 *   post:
 *     tags: [Behavioral Analysis]
 *     summary: Bulk analyze multiple users (Admin only)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userIds
 *             properties:
 *               userIds:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uuid
 *                 minItems: 1
 *                 maxItems: 50
 *               endDate:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       200:
 *         description: Bulk analysis completed
 *       400:
 *         description: Validation errors
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Admin access required
 */
router.post('/users/bulk-analyze', authenticate, requireMinRole('admin'), validateBulkUserAnalysis, behaviorController.bulkAnalyzeUsers);

/**
 * @swagger
 * /api/behavior/networks:
 *   get:
 *     tags: [Behavioral Analysis]
 *     summary: Get network behavior profiles
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *         description: Number of profiles per page
 *       - in: query
 *         name: identifier
 *         schema:
 *           type: string
 *         description: Filter by identifier (partial match)
 *       - in: query
 *         name: identifierType
 *         schema:
 *           type: string
 *           enum: [ip, mac, subnet, device]
 *         description: Filter by identifier type
 *       - in: query
 *         name: riskScore
 *         schema:
 *           type: integer
 *           minimum: 0
 *           maximum: 100
 *         description: Minimum risk score filter
 *       - in: query
 *         name: hasAnomalies
 *         schema:
 *           type: boolean
 *         description: Filter profiles with anomalies
 *     responses:
 *       200:
 *         description: Network behavior profiles retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/networks', authenticate, requireMinRole('analyst'), validatePagination, behaviorController.getNetworkBehaviorProfiles);

/**
 * @swagger
 * /api/behavior/networks/{identifierType}/{identifier}:
 *   get:
 *     tags: [Behavioral Analysis]
 *     summary: Get specific network behavior profile
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: identifierType
 *         required: true
 *         schema:
 *           type: string
 *           enum: [ip, mac, subnet, device]
 *         description: Type of network identifier
 *       - in: path
 *         name: identifier
 *         required: true
 *         schema:
 *           type: string
 *         description: Network identifier value
 *     responses:
 *       200:
 *         description: Network behavior profile retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Profile not found
 */
router.get('/networks/:identifierType/:identifier', authenticate, requireMinRole('analyst'), behaviorController.getNetworkBehaviorProfile);

/**
 * @swagger
 * /api/behavior/networks/analyze:
 *   post:
 *     tags: [Behavioral Analysis]
 *     summary: Trigger network behavior analysis
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - identifier
 *               - identifierType
 *             properties:
 *               identifier:
 *                 type: string
 *                 description: IP address, MAC address, subnet, or device ID
 *               identifierType:
 *                 type: string
 *                 enum: [ip, mac, subnet, device]
 *               endDate:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       200:
 *         description: Network behavior analysis completed
 *       400:
 *         description: Validation errors
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: No data available for analysis
 */
router.post('/networks/analyze', authenticate, requireMinRole('analyst'), validateNetworkBehaviorAnalysis, behaviorController.analyzeNetworkBehavior);

/**
 * @swagger
 * /api/behavior/threats:
 *   get:
 *     tags: [Threat Management]
 *     summary: Get threat events
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *         description: Number of events per page
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [info, low, medium, high, critical]
 *         description: Filter by severity
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [new, investigating, confirmed, false_positive, resolved, suppressed]
 *         description: Filter by status
 *       - in: query
 *         name: eventType
 *         schema:
 *           type: string
 *         description: Filter by event type
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in title and description
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Start date filter
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: End date filter
 *     responses:
 *       200:
 *         description: Threat events retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/threats', authenticate, requireMinRole('analyst'), validatePagination, validateThreatEventFilters, behaviorController.getThreatEvents);

/**
 * @swagger
 * /api/behavior/threats/{eventId}:
 *   get:
 *     tags: [Threat Management]
 *     summary: Get specific threat event
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: eventId
 *         required: true
 *         schema:
 *           type: string
 *         description: Threat event ID
 *     responses:
 *       200:
 *         description: Threat event retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Threat event not found
 */
router.get('/threats/:eventId', authenticate, requireMinRole('analyst'), behaviorController.getThreatEvent);

/**
 * @swagger
 * /api/behavior/threats/{eventId}/status:
 *   put:
 *     tags: [Threat Management]
 *     summary: Update threat event status
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: eventId
 *         required: true
 *         schema:
 *           type: string
 *         description: Threat event ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [new, investigating, confirmed, false_positive, resolved, suppressed]
 *               comment:
 *                 type: string
 *                 maxLength: 500
 *               assignedTo:
 *                 type: string
 *                 format: uuid
 *     responses:
 *       200:
 *         description: Threat event updated successfully
 *       400:
 *         description: Validation errors
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Threat event not found
 */
router.put('/threats/:eventId/status', authenticate, requireMinRole('analyst'), validateThreatEventStatusUpdate, behaviorController.updateThreatEventStatus);

/**
 * @swagger
 * /api/behavior/stats:
 *   get:
 *     tags: [Behavioral Analysis]
 *     summary: Get behavioral analysis statistics
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           pattern: ^\d+d$
 *           default: 7d
 *         description: Time period (e.g., 7d, 30d)
 *     responses:
 *       200:
 *         description: Behavioral analysis statistics retrieved successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 */
router.get('/stats', authenticate, requireMinRole('viewer'), validateBehaviorStatsQuery, behaviorController.getBehavioralAnalysisStats);

module.exports = router;