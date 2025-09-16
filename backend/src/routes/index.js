const express = require('express');
const router = express.Router();
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Import controllers
const ruleController = require('../controllers/ruleController');
const logController = require('../controllers/logController');

// Import middleware
const { authenticate, requireMinRole, optionalAuth } = require('../middleware/auth');
const { generalRateLimit } = require('../middleware/security');
const { 
  validateRule, 
  validateRuleUpdate, 
  validateLogIngestion, 
  validateUUID, 
  validatePagination,
  validateLogFilters 
} = require('../middleware/validation');

// Import route modules
const authRoutes = require('./auth');
const userRoutes = require('./users');

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'AutoSec API',
      version: '1.0.0',
      description: 'Advanced Cybersecurity Operations Platform API',
      contact: {
        name: 'AutoSec Team',
        email: 'api@autosec.io',
      },
    },
    servers: [
      {
        url: process.env.API_BASE_URL || 'http://localhost:8080/api',
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./src/routes/*.js'], // paths to files containing OpenAPI definitions
};

const specs = swaggerJsdoc(swaggerOptions);

// Swagger UI
router.use('/docs', swaggerUi.serve, swaggerUi.setup(specs, {
  explorer: true,
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'AutoSec API Documentation',
}));

// API routes with authentication and rate limiting
router.use('/auth', generalRateLimit, authRoutes);
router.use('/users', generalRateLimit, userRoutes);

/**
 * @swagger
 * /api/rules:
 *   get:
 *     tags: [Rules Management]
 *     summary: Get all blocking rules
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
 *         description: Number of rules per page
 *     responses:
 *       200:
 *         description: Rules retrieved successfully
 *       401:
 *         description: Authentication required
 */
router.get('/rules', authenticate, requireMinRole('viewer'), validatePagination, ruleController.getAllRules);

/**
 * @swagger
 * /api/rules:
 *   post:
 *     tags: [Rules Management]
 *     summary: Create new blocking rule
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - type
 *               - value
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [IP_SINGLE, IP_RANGE, COUNTRY, ORGANIZATION]
 *               value:
 *                 type: string
 *               description:
 *                 type: string
 *               is_permanent:
 *                 type: boolean
 *                 default: true
 *               expires_at:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       201:
 *         description: Rule created successfully
 *       400:
 *         description: Validation errors
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       409:
 *         description: Rule already exists
 */
router.post('/rules', authenticate, requireMinRole('operator'), validateRule, ruleController.createRule);

/**
 * @swagger
 * /api/rules/{id}:
 *   put:
 *     tags: [Rules Management]
 *     summary: Update blocking rule
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *               is_active:
 *                 type: boolean
 *               is_permanent:
 *                 type: boolean
 *               expires_at:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       200:
 *         description: Rule updated successfully
 *       400:
 *         description: Validation errors
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Rule not found
 */
router.put('/rules/:id', authenticate, requireMinRole('operator'), validateUUID, validateRuleUpdate, ruleController.updateRule);

/**
 * @swagger
 * /api/rules/{id}:
 *   delete:
 *     tags: [Rules Management]
 *     summary: Delete blocking rule
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       204:
 *         description: Rule deleted successfully
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Insufficient permissions
 *       404:
 *         description: Rule not found
 */
router.delete('/rules/:id', authenticate, requireMinRole('operator'), validateUUID, ruleController.deleteRule);

/**
 * @swagger
 * /api/logs:
 *   post:
 *     tags: [Log Management]
 *     summary: Ingest log data
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - level
 *               - source
 *               - event_type
 *               - message
 *             properties:
 *               level:
 *                 type: string
 *                 enum: [info, warn, error, debug, critical]
 *               source:
 *                 type: string
 *               event_type:
 *                 type: string
 *               message:
 *                 type: string
 *               timestamp:
 *                 type: string
 *                 format: date-time
 *               ip_address:
 *                 type: string
 *                 format: ipv4
 *               user_id:
 *                 type: string
 *                 format: uuid
 *               device_id:
 *                 type: string
 *               metadata:
 *                 type: object
 *     responses:
 *       202:
 *         description: Log accepted for processing
 *       400:
 *         description: Validation errors
 */
router.post('/logs', optionalAuth, validateLogIngestion, logController.ingestLog);

/**
 * @swagger
 * /api/logs:
 *   get:
 *     tags: [Log Management]
 *     summary: Retrieve logs with filtering
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: level
 *         schema:
 *           type: string
 *           enum: [info, warn, error, debug, critical]
 *       - in: query
 *         name: source
 *         schema:
 *           type: string
 *       - in: query
 *         name: event_type
 *         schema:
 *           type: string
 *       - in: query
 *         name: ip_address
 *         schema:
 *           type: string
 *           format: ipv4
 *       - in: query
 *         name: search
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
 *         description: Logs retrieved successfully
 *       401:
 *         description: Authentication required
 */
router.get('/logs', authenticate, requireMinRole('viewer'), validatePagination, validateLogFilters, logController.getLogs);

/**
 * @swagger
 * /api/geoip:
 *   get:
 *     tags: [Utilities]
 *     summary: Get GeoIP information for an IP address
 *     parameters:
 *       - in: query
 *         name: ip
 *         required: true
 *         schema:
 *           type: string
 *           format: ipv4
 *         description: IP address to lookup
 *     responses:
 *       200:
 *         description: GeoIP information retrieved successfully
 *       400:
 *         description: IP address is required
 *       404:
 *         description: GeoIP information not found
 */
router.get('/geoip', ruleController.getGeoIpInfo);

// Health check endpoint
/**
 * @swagger
 * /api/health:
 *   get:
 *     tags: [System]
 *     summary: Health check endpoint
 *     responses:
 *       200:
 *         description: System is healthy
 */
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'AutoSec API is healthy',
    timestamp: new Date().toISOString(),
    version: process.env.API_VERSION || '1.0.0',
  });
});

module.exports = router;