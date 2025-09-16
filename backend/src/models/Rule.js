const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const { RULE_TYPES } = require('../utils/constants');

const Rule = sequelize.define('Rule', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  type: {
    type: DataTypes.ENUM(...Object.values(RULE_TYPES)),
    allowNull: false,
    comment: 'Type of rule: IP_SINGLE, IP_RANGE, COUNTRY, ORGANIZATION',
  },
  value: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true, // Ensure unique values for blocking
    comment: 'The IP, CIDR, country code, or organization name/ASN',
  },
  description: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Optional description for the rule',
  },
  is_permanent: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
    comment: 'True if the rule is permanent, false if temporary',
  },
  expires_at: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Timestamp when a temporary rule expires',
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    allowNull: false,
    comment: 'Whether the rule is currently active',
  },
  source: {
    type: DataTypes.STRING,
    defaultValue: 'manual',
    allowNull: false,
    comment: 'Source of the rule (e.g., manual, threat_feed, behavioral_analysis)',
  },
}, {
  tableName: 'blocklist_rules',
  timestamps: true, // Adds createdAt and updatedAt fields
});

module.exports = Rule;