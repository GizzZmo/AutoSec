const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    required: true,
  },
  level: {
    type: String,
    required: true,
    enum: ['info', 'warn', 'error', 'debug', 'critical'],
  },
  source: {
    type: String,
    required: true,
    comment: 'e.g., firewall, application, system, user_activity',
  },
  event_type: {
    type: String,
    required: true,
    comment: 'e.g., connection_attempt, login_failure, data_transfer, policy_violation',
  },
  message: {
    type: String,
    required: true,
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed, // Flexible field for any additional data
    default: {},
  },
  ip_address: {
    type: String,
    index: true, // Index for faster lookups
    allowNull: true,
  },
  user_id: {
    type: String,
    allowNull: true,
  },
  device_id: {
    type: String,
    allowNull: true,
  },
  country: {
    type: String,
    allowNull: true,
  },
  region: {
    type: String,
    allowNull: true,
  },
  asn: {
    type: String,
    allowNull: true,
  },
  organization: {
    type: String,
    allowNull: true,
  }
}, {
  timestamps: true, // Adds createdAt and updatedAt
});

// Create a text index for full-text search on message and metadata
logSchema.index({ message: 'text', 'metadata.details': 'text' });

const Log = mongoose.model('Log', logSchema);

module.exports = Log;