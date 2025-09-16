const Rule = require('../models/Rule');
const { RULE_TYPES } = require('../utils/constants');
const geoIpService = require('../services/geoIpService');
const enforcementService = require('../services/enforcementService'); // Mock service

// Helper to validate rule value based on type
const validateRuleValue = async (type, value) => {
  switch (type) {
    case RULE_TYPES.IP_SINGLE:
      // Basic IP validation (can be enhanced with regex)
      return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value);
    case RULE_TYPES.IP_RANGE:
      // Basic CIDR validation (can be enhanced)
      return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])$/.test(value);
    case RULE_TYPES.COUNTRY:
      // Check if it's a valid country code (e.g., ISO 3166-1 alpha-2)
      // For simplicity, we'll just check if it's 2 uppercase letters
      return /^[A-Z]{2}$/.test(value);
    case RULE_TYPES.ORGANIZATION:
      // For organization, any string is currently valid, but could be validated against known ASNs/org names
      return typeof value === 'string' && value.length > 0;
    default:
      return false;
  }
};

// Get all rules
exports.getAllRules = async (req, res) => {
  try {
    const rules = await Rule.findAll({
      order: [['createdAt', 'DESC']]
    });
    res.status(200).json(rules);
  } catch (error) {
    console.error('Error fetching rules:', error);
    res.status(500).json({ message: 'Error fetching rules', error: error.message });
  }
};

// Create a new rule
exports.createRule = async (req, res) => {
  const { type, value, description, is_permanent, expires_at } = req.body;

  if (!type || !value) {
    return res.status(400).json({ message: 'Rule type and value are required.' });
  }

  if (!Object.values(RULE_TYPES).includes(type)) {
    return res.status(400).json({ message: `Invalid rule type. Must be one of: ${Object.values(RULE_TYPES).join(', ')}` });
  }

  if (!(await validateRuleValue(type, value))) {
    return res.status(400).json({ message: `Invalid value format for rule type '${type}'.` });
  }

  if (!is_permanent && !expires_at) {
    return res.status(400).json({ message: 'Temporary rules require an expiry date.' });
  }
  if (is_permanent && expires_at) {
    return res.status(400).json({ message: 'Permanent rules cannot have an expiry date.' });
  }

  try {
    // Check for existing rule with the same value
    const existingRule = await Rule.findOne({ where: { value } });
    if (existingRule) {
      return res.status(409).json({ message: `A rule with value '${value}' already exists.` });
    }

    let ruleData = {
      type,
      value,
      description,
      is_permanent: is_permanent || false,
      is_active: true,
      source: 'manual'
    };

    if (!is_permanent) {
      ruleData.expires_at = new Date(expires_at);
      if (ruleData.expires_at <= new Date()) {
        return res.status(400).json({ message: 'Expiry date must be in the future.' });
      }
    }

    const newRule = await Rule.create(ruleData);

    // Simulate pushing rule to enforcement service
    enforcementService.applyRule(newRule);

    res.status(201).json(newRule);
  } catch (error) {
    console.error('Error creating rule:', error);
    res.status(500).json({ message: 'Error creating rule', error: error.message });
  }
};

// Update a rule
exports.updateRule = async (req, res) => {
  const { id } = req.params;
  const { description, is_active, is_permanent, expires_at } = req.body;

  try {
    const rule = await Rule.findByPk(id);
    if (!rule) {
      return res.status(404).json({ message: 'Rule not found.' });
    }

    if (typeof is_active === 'boolean') {
      rule.is_active = is_active;
    }
    if (description !== undefined) {
      rule.description = description;
    }

    if (typeof is_permanent === 'boolean') {
      rule.is_permanent = is_permanent;
      if (is_permanent) {
        rule.expires_at = null; // Clear expiry for permanent rules
      } else {
        if (!expires_at) {
          return res.status(400).json({ message: 'Temporary rules require an expiry date.' });
        }
        rule.expires_at = new Date(expires_at);
        if (rule.expires_at <= new Date()) {
          return res.status(400).json({ message: 'Expiry date must be in the future.' });
        }
      }
    } else if (!rule.is_permanent && expires_at) { // Only update expires_at if not permanent
      rule.expires_at = new Date(expires_at);
      if (rule.expires_at <= new Date()) {
        return res.status(400).json({ message: 'Expiry date must be in the future.' });
      }
    }

    await rule.save();

    // Simulate updating rule in enforcement service
    enforcementService.updateRule(rule);

    res.status(200).json(rule);
  } catch (error) {
    console.error('Error updating rule:', error);
    res.status(500).json({ message: 'Error updating rule', error: error.message });
  }
};

// Delete a rule
exports.deleteRule = async (req, res) => {
  const { id } = req.params;
  try {
    const rule = await Rule.findByPk(id);
    if (!rule) {
      return res.status(404).json({ message: 'Rule not found.' });
    }

    await rule.destroy();

    // Simulate removing rule from enforcement service
    enforcementService.removeRule(rule);

    res.status(204).send(); // No Content
  } catch (error) {
    console.error('Error deleting rule:', error);
    res.status(500).json({ message: 'Error deleting rule', error: error.message });
  }
};

// Get GeoIP info for a given IP (for testing/demonstration)
exports.getGeoIpInfo = async (req, res) => {
  const { ip } = req.query;
  if (!ip) {
    return res.status(400).json({ message: 'IP address is required.' });
  }
  try {
    const geo = geoIpService.lookup(ip);
    if (geo) {
      res.status(200).json(geo);
    } else {
      res.status(404).json({ message: 'GeoIP information not found for this IP.' });
    }
  } catch (error) {
    console.error('Error looking up GeoIP:', error);
    res.status(500).json({ message: 'Error looking up GeoIP', error: error.message });
  }
};