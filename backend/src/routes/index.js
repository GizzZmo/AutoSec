const express = require('express');
const router = express.Router();
const ruleController = require('../controllers/ruleController');
const logController = require('../controllers/logController');

// Rule Management Endpoints
router.get('/rules', ruleController.getAllRules);
router.post('/rules', ruleController.createRule);
router.put('/rules/:id', ruleController.updateRule);
router.delete('/rules/:id', ruleController.deleteRule);

// Log Ingestion and Retrieval Endpoints
router.post('/logs', logController.ingestLog); // Endpoint for external systems to send logs
router.get('/logs', logController.getLogs); // Endpoint for frontend to retrieve logs

// GeoIP Lookup (for testing/demonstration)
router.get('/geoip', ruleController.getGeoIpInfo);

module.exports = router;