# AutoSec
AutoSec Security Dashboard

AutoSec is designed as a proactive and intelligent cybersecurity application, focusing on network-level defense with capabilities extending to user and system behavior. Its core strength lies in its dynamic IP blocklist coupled with advanced analytics to address modern cybersecurity challenges.

## Architecture Overview and Technology Choices

AutoSec follows a modular, microservices-based architecture to ensure scalability, flexibility, and ease of maintenance.

*   **Frontend (User Interface): React.js**
    *   **Choice Rationale:** React is a popular, component-based JavaScript library for building user interfaces. Its declarative nature, strong community support, and extensive ecosystem make it ideal for developing complex, interactive dashboards.
*   **Backend Services (APIs): Node.js with Express.js**
    *   **Choice Rationale:** Node.js is an excellent choice for building fast, scalable network applications and APIs. Express.js provides a robust and flexible framework for web applications. Its non-blocking I/O model is well-suited for handling concurrent requests, which is crucial for services like telemetry ingestion and real-time rule management.
    *   **Services Implemented (Core):**
        *   **Configuration Service:** Manages IP blocklist rules and system settings.
        *   **Telemetry & Ingestion Service:** Collects network flow data, system logs, and user activity logs.
    *   **Services Conceptualized (Advanced):**
        *   **Threat Intelligence Service:** Integrates with external Geo-IP databases and threat feeds.
        *   **Enforcement Service:** Communicates with network devices (firewalls) to apply blocking rules.
        *   **Behavioral Analysis Engine:** Processes ingested data using AI/ML models for anomaly detection.
        *   **Alerting & Orchestration Service:** Generates alerts and manages incident workflows.
*   **Database:**
    *   **Relational DB (PostgreSQL):**
        *   **Choice Rationale:** PostgreSQL is a powerful, open-source object-relational database system known for its reliability, feature robustness, and performance. It's ideal for structured data like user accounts, rule configurations, policy definitions, and audit logs, where data integrity and complex querying are paramount.
    *   **NoSQL DB (MongoDB):**
        *   **Choice Rationale:** MongoDB is a flexible, document-oriented NoSQL database. It's well-suited for storing large volumes of unstructured or semi-structured data, such as raw logs, telemetry data, and analytical results. Its scalability and ability to handle varying data schemas make it perfect for log ingestion.
*   **Message Broker (RabbitMQ):**
    *   **Choice Rationale:** RabbitMQ is a widely adopted open-source message broker that implements the Advanced Message Queuing Protocol (AMQP). It provides reliable asynchronous communication between microservices, ensuring that data (like ingested logs or rule updates) is processed even if a consumer service is temporarily unavailable. This decouples services and improves system resilience.
*   **Containerization:** Docker
    *   **Choice Rationale:** Docker enables packaging applications and their dependencies into isolated containers, ensuring consistent environments across development, testing, and production. This simplifies deployment and reduces "it works on my machine" issues.
*   **Orchestration:** Docker Compose (for local development), Kubernetes (for production - conceptual)
    *   **Choice Rationale:** Docker Compose allows defining and running multi-container Docker applications locally. For production, Kubernetes is the industry standard for orchestrating containerized applications at scale, providing features like self-healing, scaling, and load balancing.

This architecture provides a robust foundation for AutoSec, allowing it to be scalable, maintainable, and adaptable to evolving cybersecurity threats.

---

## AutoSec Application Code

Below is the complete code for a simplified version of AutoSec, focusing on the core dynamic IP blocklist and basic log ingestion, along with the necessary infrastructure setup.

### File Structure

```
autosec/
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.js
│   │   │   └── Sidebar.js
│   │   ├── pages/
│   │   │   ├── Blocklist.js
│   │   │   ├── Dashboard.js
│   │   │   └── Logs.js
│   │   ├── services/
│   │   │   └── api.js
│   │   ├── App.js
│   │   ├── index.css
│   │   └── index.js
│   ├── package.json
│   └── README.md
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   ├── db.js
│   │   │   └── rabbitmq.js
│   │   ├── controllers/
│   │   │   ├── logController.js
│   │   │   └── ruleController.js
│   │   ├── models/
│   │   │   ├── Log.js
│   │   │   └── Rule.js
│   │   ├── routes/
│   │   │   └── index.js
│   │   ├── services/
│   │   │   ├── enforcementService.js (Mock)
│   │   │   ├── geoIpService.js
│   │   │   ├── rabbitmqConsumer.js
│   │   │   └── threatIntelService.js (Mock)
│   │   ├── utils/
│   │   │   └── constants.js
│   │   ├── app.js
│   │   └── server.js
│   ├── .env.example
│   ├── Dockerfile
│   ├── package.json
│   └── README.md
├── database/
│   ├── postgres/
│   │   └── init.sql
│   └── mongo/
│       └── README.md (No specific init file needed for MongoDB, it's schema-less)
├── data/
│   └── geoip/
│       └── GeoLite2-City.mmdb (Placeholder - download this file)
├── docker-compose.yml
└── README.md
```

### 1. Backend (Node.js with Express)

The backend will handle API requests for managing blocklist rules, ingesting logs, and interacting with databases and the message broker.

**`backend/package.json`**

```json
{
  "name": "autosec-backend",
  "version": "1.0.0",
  "description": "AutoSec Backend Services",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js"
  },
  "keywords": [],
  "author": "Gemini AI",
  "license": "MIT",
  "dependencies": {
    "amqplib": "^0.10.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "geoip-lite": "^1.4.9",
    "mongoose": "^8.4.1",
    "pg": "^8.11.5",
    "pg-hstore": "^2.3.4",
    "sequelize": "^6.37.3",
    "sequelize-cli": "^6.6.2"
  },
  "devDependencies": {
    "nodemon": "^3.1.0"
  }
}
```

**`backend/.env.example`**

```
PORT=8080

# PostgreSQL
PG_HOST=autosec-postgres
PG_PORT=5432
PG_USER=autosec_user
PG_PASSWORD=autosec_password
PG_DATABASE=autosec_db

# MongoDB
MONGO_URI=mongodb://autosec-mongodb:27017/autosec_logs

# RabbitMQ
RABBITMQ_URL=amqp://guest:guest@autosec-rabbitmq:5672

# GeoIP
GEOIP_DB_PATH=/app/data/geoip/GeoLite2-City.mmdb
```

**`backend/Dockerfile`**

```dockerfile
# Use an official Node.js runtime as a parent image
FROM node:20-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json (if any)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 8080

# Mount GeoIP data volume (will be mounted by docker-compose/k8s)
# VOLUME /app/data/geoip

# Command to run the application
CMD ["npm", "start"]
```

**`backend/src/server.js`**

```javascript
require('dotenv').config();
const app = require('./app');
const { sequelize } = require('./config/db');
const { connectMongoDB } = require('./config/db');
const { connectRabbitMQ, consumeMessages } = require('./config/rabbitmq');
const rabbitmqConsumer = require('./services/rabbitmqConsumer'); // Import the consumer

const PORT = process.env.PORT || 8080;

async function startServer() {
  try {
    // Connect to PostgreSQL
    await sequelize.authenticate();
    console.log('PostgreSQL connection has been established successfully.');
    await sequelize.sync(); // Sync models with database (creates tables if they don't exist)
    console.log('PostgreSQL models synced.');

    // Connect to MongoDB
    await connectMongoDB();
    console.log('MongoDB connection has been established successfully.');

    // Connect to RabbitMQ and start consuming
    await connectRabbitMQ();
    console.log('RabbitMQ connection has been established successfully.');
    consumeMessages('log_queue', rabbitmqConsumer.processLogMessage); // Start consuming logs

    // Start the Express server
    app.listen(PORT, () => {
      console.log(`AutoSec Backend running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Unable to connect to the database or start server:', error);
    process.exit(1); // Exit with failure code
  }
}

startServer();
```

**`backend/src/app.js`**

```javascript
const express = require('express');
const cors = require('cors');
const apiRoutes = require('./routes');

const app = express();

// Middleware
app.use(cors()); // Enable CORS for frontend communication
app.use(express.json()); // Parse JSON request bodies

// API Routes
app.use('/api', apiRoutes);

// Basic health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'AutoSec backend is healthy' });
});

// Error handling middleware (basic)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

module.exports = app;
```

**`backend/src/config/db.js`**

```javascript
const { Sequelize } = require('sequelize');
const mongoose = require('mongoose');

// PostgreSQL connection
const sequelize = new Sequelize(
  process.env.PG_DATABASE,
  process.env.PG_USER,
  process.env.PG_PASSWORD,
  {
    host: process.env.PG_HOST,
    port: process.env.PG_PORT,
    dialect: 'postgres',
    logging: false, // Set to true to see SQL queries
  }
);

// MongoDB connection
const connectMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

module.exports = { sequelize, connectMongoDB };
```

**`backend/src/config/rabbitmq.js`**

```javascript
const amqp = require('amqplib');

let channel;

const connectRabbitMQ = async () => {
  try {
    const connection = await amqp.connect(process.env.RABBITMQ_URL);
    channel = await connection.createChannel();
    console.log('RabbitMQ channel created.');
  } catch (error) {
    console.error('Failed to connect to RabbitMQ:', error);
    process.exit(1);
  }
};

const publishMessage = async (queue, message) => {
  if (!channel) {
    console.error('RabbitMQ channel not established.');
    return;
  }
  try {
    await channel.assertQueue(queue, { durable: true });
    channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), { persistent: true });
    // console.log(`Message sent to queue ${queue}:`, message);
  } catch (error) {
    console.error(`Failed to publish message to queue ${queue}:`, error);
  }
};

const consumeMessages = async (queue, callback) => {
  if (!channel) {
    console.error('RabbitMQ channel not established.');
    return;
  }
  try {
    await channel.assertQueue(queue, { durable: true });
    channel.consume(queue, (msg) => {
      if (msg !== null) {
        callback(JSON.parse(msg.content.toString()));
        channel.ack(msg);
      }
    }, { noAck: false });
    console.log(`Started consuming messages from queue: ${queue}`);
  } catch (error) {
    console.error(`Failed to consume messages from queue ${queue}:`, error);
  }
};

module.exports = { connectRabbitMQ, publishMessage, consumeMessages };
```

**`backend/src/models/Rule.js`**

```javascript
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
```

**`backend/src/models/Log.js`**

```javascript
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
```

**`backend/src/controllers/ruleController.js`**

```javascript
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
```

**`backend/src/controllers/logController.js`**

```javascript
const Log = require('../models/Log');
const { publishMessage } = require('../config/rabbitmq');
const geoIpService = require('../services/geoIpService');

// Ingest logs (via API endpoint, then publish to RabbitMQ)
exports.ingestLog = async (req, res) => {
  const { timestamp, level, source, event_type, message, metadata, ip_address, user_id, device_id } = req.body;

  if (!level || !source || !event_type || !message) {
    return res.status(400).json({ message: 'Missing required log fields: level, source, event_type, message.' });
  }

  const logData = {
    timestamp: timestamp ? new Date(timestamp) : new Date(),
    level,
    source,
    event_type,
    message,
    metadata: metadata || {},
    ip_address,
    user_id,
    device_id,
  };

  // Perform GeoIP lookup if an IP address is provided
  if (ip_address) {
    const geo = geoIpService.lookup(ip_address);
    if (geo) {
      logData.country = geo.country;
      logData.region = geo.region;
      logData.asn = geo.asn;
      logData.organization = geo.organization;
    }
  }

  try {
    // Publish the log to RabbitMQ for asynchronous processing/storage
    await publishMessage('log_queue', logData);
    res.status(202).json({ message: 'Log accepted for processing.' });
  } catch (error) {
    console.error('Error ingesting log:', error);
    res.status(500).json({ message: 'Error ingesting log', error: error.message });
  }
};

// Get logs from MongoDB (with basic filtering/pagination)
exports.getLogs = async (req, res) => {
  const { level, source, event_type, search, ip_address, page = 1, limit = 20 } = req.query;
  const query = {};

  if (level) query.level = level;
  if (source) query.source = source;
  if (event_type) query.event_type = event_type;
  if (ip_address) query.ip_address = ip_address;

  if (search) {
    query.$or = [
      { message: { $regex: search, $options: 'i' } },
      { 'metadata.details': { $regex: search, $options: 'i' } }, // Example for metadata search
    ];
  }

  try {
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const logs = await Log.find(query)
      .sort({ timestamp: -1 }) // Sort by newest first
      .skip(skip)
      .limit(parseInt(limit));

    const totalLogs = await Log.countDocuments(query);

    res.status(200).json({
      data: logs,
      currentPage: parseInt(page),
      totalPages: Math.ceil(totalLogs / parseInt(limit)),
      totalLogs,
    });
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ message: 'Error fetching logs', error: error.message });
  }
};
```

**`backend/src/routes/index.js`**

```javascript
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
```

**`backend/src/services/enforcementService.js` (Mock)**

```javascript
// This is a mock service. In a real application, this would interact with
// firewalls (e.g., Palo Alto, Cisco ASA, iptables), SDN controllers, or
// other network security devices via their APIs or CLI.

const applyRule = (rule) => {
  console.log(`[Enforcement Service] Applying rule: ${rule.type} - ${rule.value} (ID: ${rule.id})`);
  // Example: Call firewall API to add a blocking rule
  // firewallApi.addRule({ type: rule.type, value: rule.value, action: 'deny' });
};

const updateRule = (rule) => {
  console.log(`[Enforcement Service] Updating rule: ${rule.type} - ${rule.value} (ID: ${rule.id}, Active: ${rule.is_active})`);
  // Example: Call firewall API to modify or activate/deactivate a rule
  // firewallApi.updateRule({ id: rule.id, isActive: rule.is_active });
};

const removeRule = (rule) => {
  console.log(`[Enforcement Service] Removing rule: ${rule.type} - ${rule.value} (ID: ${rule.id})`);
  // Example: Call firewall API to remove a blocking rule
  // firewallApi.removeRule({ id: rule.id });
};

module.exports = {
  applyRule,
  updateRule,
  removeRule,
};
```

**`backend/src/services/geoIpService.js`**

```javascript
const geoip = require('geoip-lite');
const path = require('path');
const fs = require('fs');

// Path to the GeoLite2-City.mmdb file
const geoIpDbPath = process.env.GEOIP_DB_PATH || path.join(__dirname, '../../data/geoip/GeoLite2-City.mmdb');

// Check if the GeoIP database file exists
if (!fs.existsSync(geoIpDbPath)) {
  console.warn(`GeoIP database not found at ${geoIpDbPath}. GeoIP lookups will not work.`);
  console.warn('Please download GeoLite2-City.mmdb from MaxMind and place it in the data/geoip directory.');
  console.warn('You can get a free GeoLite2 database from: https://dev.maxmind.com/geoip/downloads/geolite2/ (requires registration)');
} else {
  // Load the database (geoip-lite handles this internally when lookup is called)
  // We just need to ensure the path is set if it's not default
  // geoip.set
  console.log(`GeoIP database loaded from: ${geoIpDbPath}`);
}

const lookup = (ip) => {
  if (!fs.existsSync(geoIpDbPath)) {
    return null; // Cannot perform lookup if DB is missing
  }
  const geo = geoip.lookup(ip);
  if (geo) {
    return {
      range: geo.range,
      country: geo.country,
      region: geo.region,
      city: geo.city,
      ll: geo.ll, // latitude, longitude
      metro: geo.metro,
      zip: geo.zip,
      asn: geo.asn, // Autonomous System Number
      organization: geo.organization, // Organization name
    };
  }
  return null;
};

module.exports = { lookup };
```

**`backend/src/services/rabbitmqConsumer.js`**

```javascript
const Log = require('../models/Log');

// This function will be called by the RabbitMQ consumer when a new message arrives
const processLogMessage = async (logData) => {
  try {
    // Save the log to MongoDB
    const newLog = new Log(logData);
    await newLog.save();
    // console.log('Log saved to MongoDB:', newLog._id);

    // Here you would also trigger other services based on the log:
    // - Behavioral Analysis Engine: Send log for anomaly detection
    // - Alerting Service: Check for critical events and generate alerts
    // - Incident Response: Trigger playbooks for specific event types

  } catch (error) {
    console.error('Error processing log message from RabbitMQ:', error);
  }
};

module.exports = { processLogMessage };
```

**`backend/src/services/threatIntelService.js` (Mock)**

```javascript
// This is a mock service. In a real application, this would:
// 1. Periodically fetch data from various threat intelligence feeds (e.g., AbuseIPDB, AlienVault OTX, custom feeds).
// 2. Parse the data and identify malicious IPs, domains, hashes, etc.
// 3. Update the AutoSec database with new threat indicators.
// 4. Potentially trigger automated blocklist updates via the RuleController.

const fetchThreatFeeds = async () => {
  console.log('[Threat Intelligence Service] Fetching threat feeds...');
  // Simulate fetching data
  await new Promise(resolve => setTimeout(resolve, 5000)); // Simulate network delay

  const maliciousIps = [
    '1.1.1.1',
    '2.2.2.0/28',
    '100.100.100.100',
    // ... more IPs from feeds
  ];
  const maliciousCountries = ['KP', 'IR']; // North Korea, Iran

  console.log('[Threat Intelligence Service] New malicious IPs/countries identified.');

  // In a real scenario, this would interact with the RuleController
  // to add/update rules based on threat intel.
  // Example:
  // maliciousIps.forEach(ip => {
  //   // Call ruleController.createRule or a dedicated internal service
  //   // to add these as 'threat_feed' sourced rules.
  // });
  // maliciousCountries.forEach(country => {
  //   // Add country blocking rules
  // });

  return { maliciousIps, maliciousCountries };
};

// Example of how to run this periodically
// setInterval(fetchThreatFeeds, 60 * 60 * 1000); // Every hour

module.exports = {
  fetchThreatFeeds,
};
```

**`backend/src/utils/constants.js`**

```javascript
const RULE_TYPES = {
  IP_SINGLE: 'IP_SINGLE',
  IP_RANGE: 'IP_RANGE',
  COUNTRY: 'COUNTRY',
  ORGANIZATION: 'ORGANIZATION',
};

module.exports = {
  RULE_TYPES,
};
```

### 2. Database (PostgreSQL & MongoDB)

**`database/postgres/init.sql`**

```sql
-- Create the blocklist_rules table
CREATE TABLE IF NOT EXISTS blocklist_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL, -- e.g., 'IP_SINGLE', 'IP_RANGE', 'COUNTRY', 'ORGANIZATION'
    value VARCHAR(255) NOT NULL UNIQUE, -- The IP, CIDR, country code, or organization name/ASN
    description TEXT,
    is_permanent BOOLEAN DEFAULT FALSE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    source VARCHAR(100) DEFAULT 'manual' NOT NULL, -- e.g., 'manual', 'threat_feed', 'behavioral_analysis'
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_type ON blocklist_rules (type);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_value ON blocklist_rules (value);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_is_active ON blocklist_rules (is_active);
CREATE INDEX IF NOT EXISTS idx_blocklist_rules_expires_at ON blocklist_rules (expires_at) WHERE expires_at IS NOT NULL;

-- Optional: Function to update "updatedAt" automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW."updatedAt" = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Optional: Trigger to call the function before update
DROP TRIGGER IF EXISTS update_blocklist_rules_updated_at ON blocklist_rules;
CREATE TRIGGER update_blocklist_rules_updated_at
BEFORE UPDATE ON blocklist_rules
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Insert some sample data (optional)
INSERT INTO blocklist_rules (type, value, description, is_permanent, is_active, source) VALUES
('IP_SINGLE', '192.0.2.1', 'Known attacker IP from threat feed', TRUE, TRUE, 'threat_feed'),
('IP_RANGE', '10.0.0.0/8', 'Internal network range (example, usually not blocked)', TRUE, FALSE, 'manual'),
('COUNTRY', 'CN', 'Blocking traffic from China due to high risk', TRUE, TRUE, 'manual'),
('COUNTRY', 'RU', 'Blocking traffic from Russia', TRUE, TRUE, 'manual'),
('IP_SINGLE', '203.0.113.45', 'Temporary block for suspicious activity', FALSE, TRUE, 'manual', NOW() + INTERVAL '1 day');
```

**`database/mongo/README.md`**

```
# MongoDB Setup

MongoDB is used for storing logs and telemetry data. As a NoSQL document database, it does not require a predefined schema file like PostgreSQL. The schema is defined within the Node.js application's `backend/src/models/Log.js` file.

When the `autosec-mongodb` service starts via Docker Compose, it will create the `autosec_logs` database automatically upon the first connection and data insertion from the backend.

No manual initialization script is typically needed for MongoDB in this setup.
```

### 3. Frontend (React)

**`frontend/package.json`**

```json
{
  "name": "autosec-frontend",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@testing-library/jest-dom": "^5.17.0",
    "@testing-library/react": "^13.4.0",
    "@testing-library/user-event": "^13.5.0",
    "axios": "^1.7.2",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.23.1",
    "react-scripts": "5.0.1",
    "web-vitals": "^2.1.4"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app",
      "react-app/jest"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
```

**`frontend/Dockerfile`**

```dockerfile
# Stage 1: Build the React application
FROM node:20-alpine as build-stage

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Serve the application with Nginx
FROM nginx:stable-alpine as production-stage

# Copy the build output from the build stage
COPY --from=build-stage /app/build /usr/share/nginx/html

# Copy custom Nginx configuration (optional, for more advanced setups)
# COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

**`frontend/src/index.js`**

```javascript
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

reportWebVitals();
```

**`frontend/src/index.css`**

```css
/* Basic Cyberpunk-ish theme */
body {
  margin: 0;
  font-family: 'Share Tech Mono', monospace, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background-color: #1a1a2e; /* Dark blue/purple */
  color: #00ff00; /* Neon green */
  overflow-x: hidden;
}

code {
  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',
    monospace;
}

#root {
  display: flex;
  min-height: 100vh;
}

.app-container {
  display: flex;
  width: 100%;
}

.main-content {
  flex-grow: 1;
  padding: 20px;
  background-color: #0f0f1a; /* Slightly darker background for content */
  border-left: 1px solid #00ff00;
}

/* Header */
.header {
  background-color: #0a0a1a;
  color: #00ffff; /* Neon cyan */
  padding: 15px 20px;
  font-size: 1.5em;
  border-bottom: 1px solid #00ffff;
  text-align: center;
}

/* Sidebar */
.sidebar {
  width: 200px;
  background-color: #0a0a1a;
  padding: 20px;
  border-right: 1px solid #00ff00;
}

.sidebar nav ul {
  list-style: none;
  padding: 0;
}

.sidebar nav li {
  margin-bottom: 15px;
}

.sidebar nav a {
  color: #00ff00;
  text-decoration: none;
  font-size: 1.1em;
  display: block;
  padding: 8px 10px;
  border: 1px solid transparent;
  transition: all 0.3s ease;
}

.sidebar nav a:hover,
.sidebar nav a.active {
  color: #00ffff;
  border-color: #00ffff;
  background-color: #2a2a4a;
  box-shadow: 0 0 10px #00ffff;
}

/* General styles for forms, tables, buttons */
.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  color: #00ffff;
}

.form-group input[type="text"],
.form-group input[type="number"],
.form-group input[type="datetime-local"],
.form-group select,
.form-group textarea {
  width: calc(100% - 20px);
  padding: 10px;
  background-color: #2a2a4a;
  border: 1px solid #00ffff;
  color: #00ff00;
  border-radius: 3px;
  font-size: 1em;
}

.form-group input[type="checkbox"] {
  margin-right: 10px;
}

button {
  background-color: #00ffff;
  color: #1a1a2e;
  border: none;
  padding: 10px 20px;
  cursor: pointer;
  font-size: 1em;
  border-radius: 3px;
  transition: background-color 0.3s ease, color 0.3s ease;
}

button:hover {
  background-color: #00ff00;
  color: #1a1a2e;
  box-shadow: 0 0 10px #00ff00;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 20px;
}

table th, table td {
  border: 1px solid #00ffff;
  padding: 10px;
  text-align: left;
}

table th {
  background-color: #2a2a4a;
  color: #00ffff;
}

table tr:nth-child(even) {
  background-color: #1a1a2e;
}

table tr:hover {
  background-color: #2a2a4a;
}

.status-active {
  color: #00ff00; /* Neon green */
}

.status-inactive {
  color: #ff0000; /* Red */
}

.status-expired {
  color: #ffcc00; /* Yellow/Orange */
}

.pagination {
  display: flex;
  justify-content: center;
  margin-top: 20px;
}

.pagination button {
  margin: 0 5px;
  background-color: #2a2a4a;
  color: #00ffff;
  border: 1px solid #00ffff;
}

.pagination button:disabled {
  background-color: #1a1a2e;
  color: #555;
  border-color: #555;
  cursor: not-allowed;
}

.pagination button.active {
  background-color: #00ffff;
  color: #1a1a2e;
}
```

**`frontend/src/App.js`**

```javascript
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Blocklist from './pages/Blocklist';
import Logs from './pages/Logs';
import './index.css'; // Import the main CSS file

function App() {
  return (
    <Router>
      <Header />
      <div className="app-container">
        <Sidebar />
        <div className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/blocklist" element={<Blocklist />} />
            <Route path="/logs" element={<Logs />} />
            {/* Add more routes for other features */}
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;
```

**`frontend/src/components/Header.js`**

```javascript
import React from 'react';

function Header() {
  return (
    <header className="header">
      <h1>AutoSec: CyberSec Operations Console</h1>
    </header>
  );
}

export default Header;
```

**`frontend/src/components/Sidebar.js`**

```javascript
import React from 'react';
import { NavLink } from 'react-router-dom';

function Sidebar() {
  return (
    <aside className="sidebar">
      <nav>
        <ul>
          <li>
            <NavLink to="/" end>
              Dashboard
            </NavLink>
          </li>
          <li>
            <NavLink to="/blocklist">
              Dynamic Blocklist
            </NavLink>
          </li>
          <li>
            <NavLink to="/logs">
              Telemetry Logs
            </NavLink>
          </li>
          {/* Add more navigation links here */}
          <li>
            <NavLink to="/attack-surface" disabled>
              Attack Surface (WIP)
            </NavLink>
          </li>
          <li>
            <NavLink to="/behavioral-analysis" disabled>
              Behavioral Analysis (WIP)
            </NavLink>
          </li>
          <li>
            <NavLink to="/segmentation" disabled>
              Network Segmentation (WIP)
            </NavLink>
          </li>
          <li>
            <NavLink to="/incident-response" disabled>
              Incident Response (WIP)
            </NavLink>
          </li>
        </ul>
      </nav>
    </aside>
  );
}

export default Sidebar;
```

**`frontend/src/pages/Dashboard.js`**

```javascript
import React from 'react';

function Dashboard() {
  return (
    <div>
      <h2>System Overview</h2>
      <p>Welcome to the AutoSec CyberSec Operations Console.</p>
      <p>This dashboard provides a high-level overview of your network security posture.</p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px', marginTop: '30px' }}>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Active Blocklist Rules</h3>
          <p style={{ fontSize: '2em', color: '#00ff00' }}>150</p>
          <p>Currently active rules protecting your perimeter.</p>
        </div>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Logs Ingested (24h)</h3>
          <p style={{ fontSize: '2em', color: '#00ffff' }}>1,234,567</p>
          <p>Total telemetry events processed in the last 24 hours.</p>
        </div>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Critical Alerts (7d)</h3>
          <p style={{ fontSize: '2em', color: '#ff0000' }}>5</p>
          <p>High-severity incidents requiring immediate attention.</p>
        </div>
        <div style={{ border: '1px solid #00ffff', padding: '20px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
          <h3>Blocked Attempts (24h)</h3>
          <p style={{ fontSize: '2em', color: '#ffcc00' }}>87,654</p>
          <p>Connections denied by AutoSec blocklist rules.</p>
        </div>
      </div>

      <h3 style={{ marginTop: '40px' }}>Recent Activity Feed</h3>
      <ul style={{ listStyle: 'none', padding: 0 }}>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#00ff00' }}>[2025-07-23 16:05]</span> New IP_SINGLE rule added: 1.2.3.4 (Manual)
        </li>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#00ffff' }}>[2025-07-23 15:50]</span> Log ingestion spike detected (120% above baseline)
        </li>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#ff0000' }}>[2025-07-23 15:30]</span> Critical: Brute-force attempt detected from 203.0.113.10
        </li>
        <li style={{ borderBottom: '1px dashed #00ffff', padding: '10px 0' }}>
          <span style={{ color: '#00ff00' }}>[2025-07-23 15:00]</span> Country block for 'KP' updated (Threat Feed)
        </li>
      </ul>
    </div>
  );
}

export default Dashboard;
```

**`frontend/src/pages/Blocklist.js`**

```javascript
import React, { useState, useEffect } from 'react';
import api from '../services/api';

const RULE_TYPES = {
  IP_SINGLE: 'IP_SINGLE',
  IP_RANGE: 'IP_RANGE',
  COUNTRY: 'COUNTRY',
  ORGANIZATION: 'ORGANIZATION',
};

function Blocklist() {
  const [rules, setRules] = useState([]);
  const [newRule, setNewRule] = useState({
    type: RULE_TYPES.IP_SINGLE,
    value: '',
    description: '',
    is_permanent: true,
    expires_at: '',
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.get('/rules');
      setRules(response.data);
    } catch (err) {
      console.error('Error fetching rules:', err);
      setError('Failed to fetch rules. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setNewRule(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);

    try {
      const ruleToCreate = { ...newRule };
      if (ruleToCreate.is_permanent) {
        delete ruleToCreate.expires_at;
      } else if (ruleToCreate.expires_at) {
        // Ensure expires_at is a valid ISO string for backend
        ruleToCreate.expires_at = new Date(ruleToCreate.expires_at).toISOString();
      } else {
        setError('Temporary rules require an expiry date.');
        return;
      }

      const response = await api.post('/rules', ruleToCreate);
      setRules(prev => [response.data, ...prev]);
      setNewRule({
        type: RULE_TYPES.IP_SINGLE,
        value: '',
        description: '',
        is_permanent: true,
        expires_at: '',
      });
      setSuccessMessage('Rule added successfully!');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      console.error('Error adding rule:', err);
      setError(err.response?.data?.message || 'Failed to add rule. Please check your input.');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) {
      return;
    }
    setError(null);
    setSuccessMessage(null);
    try {
      await api.delete(`/rules/${id}`);
      setRules(prev => prev.filter(rule => rule.id !== id));
      setSuccessMessage('Rule deleted successfully!');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      console.error('Error deleting rule:', err);
      setError(err.response?.data?.message || 'Failed to delete rule.');
    }
  };

  const getStatus = (rule) => {
    if (!rule.is_active) return <span className="status-inactive">Inactive</span>;
    if (!rule.is_permanent && new Date(rule.expires_at) <= new Date()) {
      return <span className="status-expired">Expired</span>;
    }
    return <span className="status-active">Active</span>;
  };

  return (
    <div>
      <h2>Dynamic IP Blocklist</h2>

      {error && <p style={{ color: 'red' }}>{error}</p>}
      {successMessage && <p style={{ color: 'lime' }}>{successMessage}</p>}

      <h3>Add New Rule</h3>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="type">Rule Type:</label>
          <select id="type" name="type" value={newRule.type} onChange={handleChange} required>
            {Object.values(RULE_TYPES).map(type => (
              <option key={type} value={type}>{type.replace('_', ' ')}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="value">Value (IP, CIDR, Country Code, Organization):</label>
          <input
            type="text"
            id="value"
            name="value"
            value={newRule.value}
            onChange={handleChange}
            placeholder={
              newRule.type === RULE_TYPES.IP_SINGLE ? 'e.g., 192.168.1.1' :
              newRule.type === RULE_TYPES.IP_RANGE ? 'e.g., 192.168.1.0/24' :
              newRule.type === RULE_TYPES.COUNTRY ? 'e.g., US, CN, RU' :
              'e.g., Google, AS15169'
            }
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="description">Description (Optional):</label>
          <textarea
            id="description"
            name="description"
            value={newRule.description}
            onChange={handleChange}
            rows="3"
          ></textarea>
        </div>
        <div className="form-group">
          <label>
            <input
              type="checkbox"
              name="is_permanent"
              checked={newRule.is_permanent}
              onChange={handleChange}
            />
            Permanent Rule
          </label>
        </div>
        {!newRule.is_permanent && (
          <div className="form-group">
            <label htmlFor="expires_at">Expires At:</label>
            <input
              type="datetime-local"
              id="expires_at"
              name="expires_at"
              value={newRule.expires_at}
              onChange={handleChange}
              required={!newRule.is_permanent}
            />
          </div>
        )}
        <button type="submit">Add Rule</button>
      </form>

      <h3 style={{ marginTop: '40px' }}>Existing Rules</h3>
      {loading ? (
        <p>Loading rules...</p>
      ) : rules.length === 0 ? (
        <p>No rules found. Add a new rule above.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Description</th>
              <th>Source</th>
              <th>Status</th>
              <th>Expires At</th>
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map(rule => (
              <tr key={rule.id}>
                <td>{rule.type.replace('_', ' ')}</td>
                <td>{rule.value}</td>
                <td>{rule.description}</td>
                <td>{rule.source}</td>
                <td>{getStatus(rule)}</td>
                <td>{rule.is_permanent ? 'N/A' : new Date(rule.expires_at).toLocaleString()}</td>
                <td>{new Date(rule.createdAt).toLocaleString()}</td>
                <td>
                  <button onClick={() => handleDelete(rule.id)} style={{ backgroundColor: '#ff0000', color: '#fff' }}>Delete</button>
                  {/* Add an Edit button/modal here for full functionality */}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Blocklist;
```

**`frontend/src/pages/Logs.js`**

```javascript
import React, { useState, useEffect } from 'react';
import api from '../services/api';

function Logs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    level: '',
    source: '',
    event_type: '',
    ip_address: '',
    search: '',
    page: 1,
    limit: 20,
  });
  const [pagination, setPagination] = useState({
    currentPage: 1,
    totalPages: 1,
    totalLogs: 0,
  });

  useEffect(() => {
    fetchLogs();
  }, [filters.page, filters.limit]); // Refetch when page or limit changes

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const queryParams = new URLSearchParams(filters).toString();
      const response = await api.get(`/logs?${queryParams}`);
      setLogs(response.data.data);
      setPagination({
        currentPage: response.data.currentPage,
        totalPages: response.data.totalPages,
        totalLogs: response.data.totalLogs,
      });
    } catch (err) {
      console.error('Error fetching logs:', err);
      setError('Failed to fetch logs. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value, page: 1 })); // Reset to page 1 on filter change
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchLogs(); // Trigger fetch with current filters
  };

  const handlePageChange = (newPage) => {
    setFilters(prev => ({ ...prev, page: newPage }));
  };

  return (
    <div>
      <h2>Telemetry Logs</h2>

      {error && <p style={{ color: 'red' }}>{error}</p>}

      <form onSubmit={handleSearchSubmit} style={{ marginBottom: '20px', border: '1px solid #00ffff', padding: '15px', borderRadius: '5px', backgroundColor: '#1a1a2e' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
          <div className="form-group">
            <label htmlFor="level">Level:</label>
            <select id="level" name="level" value={filters.level} onChange={handleFilterChange}>
              <option value="">All</option>
              <option value="info">Info</option>
              <option value="warn">Warn</option>
              <option value="error">Error</option>
              <option value="debug">Debug</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="source">Source:</label>
            <input type="text" id="source" name="source" value={filters.source} onChange={handleFilterChange} placeholder="e.g., firewall, application" />
          </div>
          <div className="form-group">
            <label htmlFor="event_type">Event Type:</label>
            <input type="text" id="event_type" name="event_type" value={filters.event_type} onChange={handleFilterChange} placeholder="e.g., login_failure, connection_attempt" />
          </div>
          <div className="form-group">
            <label htmlFor="ip_address">IP Address:</label>
            <input type="text" id="ip_address" name="ip_address" value={filters.ip_address} onChange={handleFilterChange} placeholder="e.g., 192.168.1.1" />
          </div>
          <div className="form-group" style={{ gridColumn: 'span 2' }}>
            <label htmlFor="search">Search (Message/Metadata):</label>
            <input type="text" id="search" name="search" value={filters.search} onChange={handleFilterChange} placeholder="Search keywords..." />
          </div>
        </div>
        <button type="submit" style={{ marginTop: '15px' }}>Apply Filters</button>
      </form>

      {loading ? (
        <p>Loading logs...</p>
      ) : logs.length === 0 ? (
        <p>No logs found matching your criteria.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Level</th>
                <th>Source</th>
                <th>Event Type</th>
                <th>Message</th>
                <th>IP Address</th>
                <th>Country</th>
                <th>Organization</th>
                <th>User/Device</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log._id}>
                  <td>{new Date(log.timestamp).toLocaleString()}</td>
                  <td>{log.level}</td>
                  <td>{log.source}</td>
                  <td>{log.event_type}</td>
                  <td>{log.message}</td>
                  <td>{log.ip_address || 'N/A'}</td>
                  <td>{log.country || 'N/A'}</td>
                  <td>{log.organization || 'N/A'}</td>
                  <td>{log.user_id || log.device_id || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="pagination">
            <button onClick={() => handlePageChange(pagination.currentPage - 1)} disabled={pagination.currentPage <= 1}>
              Previous
            </button>
            <span>Page {pagination.currentPage} of {pagination.totalPages} ({pagination.totalLogs} total logs)</span>
            <button onClick={() => handlePageChange(pagination.currentPage + 1)} disabled={pagination.currentPage >= pagination.totalPages}>
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export default Logs;
```

**`frontend/src/services/api.js`**

```javascript
import axios from 'axios';

// Determine API base URL based on environment
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8080/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Optional: Add request/response interceptors for logging, error handling, etc.
api.interceptors.request.use(
  (config) => {
    // console.log('Request:', config);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    // console.log('Response:', response);
    return response;
  },
  (error) => {
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error('API Error Response:', error.response.data);
      console.error('API Error Status:', error.response.status);
      console.error('API Error Headers:', error.response.headers);
    } else if (error.request) {
      // The request was made but no response was received
      console.error('API Error Request:', error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error('API Error Message:', error.message);
    }
    return Promise.reject(error);
  }
);

export default api;
```

### 4. Docker Compose for Local Development

This `docker-compose.yml` file will orchestrate all the services for local development.

**`docker-compose.yml`**

```yaml
version: '3.8'

services:
  # PostgreSQL Database Service
  autosec-postgres:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_DB: ${PG_DATABASE}
      POSTGRES_USER: ${PG_USER}
      POSTGRES_PASSWORD: ${PG_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432" # Expose for local DB tools if needed

  # MongoDB Database Service
  autosec-mongodb:
    image: mongo:6.0-jammy
    restart: always
    volumes:
      - mongodb_data:/data/db
    ports:
      - "27017:27017" # Expose for local DB tools if needed

  # RabbitMQ Message Broker Service
  autosec-rabbitmq:
    image: rabbitmq:3-management-alpine
    restart: always
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest
    ports:
      - "5672:5672" # AMQP protocol port
      - "15672:15672" # Management UI port

  # AutoSec Backend Service
  autosec-backend:
    build: ./backend
    restart: always
    environment:
      PORT: ${PORT}
      PG_HOST: autosec-postgres
      PG_PORT: ${PG_PORT}
      PG_USER: ${PG_USER}
      PG_PASSWORD: ${PG_PASSWORD}
      PG_DATABASE: ${PG_DATABASE}
      MONGO_URI: mongodb://autosec-mongodb:27017/${MONGO_DATABASE} # MONGO_DATABASE is derived from MONGO_URI in .env
      RABBITMQ_URL: amqp://guest:guest@autosec-rabbitmq:5672
      GEOIP_DB_PATH: /app/data/geoip/GeoLite2-City.mmdb # Path inside the container
    volumes:
      - ./data/geoip:/app/data/geoip:ro # Mount GeoIP data read-only
    ports:
      - "8080:8080"
    depends_on:
      - autosec-postgres
      - autosec-mongodb
      - autosec-rabbitmq

  # AutoSec Frontend Service
  autosec-frontend:
    build: ./frontend
    restart: always
    environment:
      REACT_APP_API_BASE_URL: http://localhost:8080/api # Connects to backend via host machine's localhost
    ports:
      - "3000:80" # Nginx serves React build on port 80 inside container
    depends_on:
      - autosec-backend

volumes:
  postgres_data:
  mongodb_data:
```

### 5. Root `README.md`

**`autosec/README.md`**

```markdown
# AutoSec: CyberSec Operations Console

AutoSec is a comprehensive cybersecurity application designed for proactive network-level defense, dynamic IP blocklisting, and advanced behavioral analysis. This project demonstrates a microservices-based architecture using React for the frontend, Node.js/Express for the backend, PostgreSQL for structured data, MongoDB for logs, and RabbitMQ for asynchronous communication.

## Key Features (Implemented in this Demo)

*   **Dynamic IP Blocklist:**
    *   Add/View/Delete rules for single IPs, IP ranges (CIDR), countries, and organizations.
    *   Support for temporary and permanent rules.
    *   Basic status tracking (Active, Inactive, Expired).
*   **Telemetry Log Ingestion:**
    *   API endpoint to receive logs from various sources.
    *   Asynchronous processing and storage of logs in MongoDB via RabbitMQ.
    *   Basic GeoIP enrichment for incoming logs.
*   **Telemetry Log Viewer:**
    *   Frontend interface to view ingested logs with basic filtering and pagination.
*   **Modular Architecture:** Demonstrates a microservices setup with clear separation of concerns.

## Architecture Overview

*   **Frontend:** React.js (User Interface)
*   **Backend:** Node.js with Express.js (API Gateway, Configuration Service, Telemetry & Ingestion Service)
*   **Databases:**
    *   PostgreSQL (for structured data like blocklist rules)
    *   MongoDB (for unstructured log and telemetry data)
*   **Message Broker:** RabbitMQ (for asynchronous communication between services)
*   **Containerization:** Docker
*   **Orchestration:** Docker Compose (for local development)

## Getting Started

### Prerequisites

*   Docker Desktop (or Docker Engine and Docker Compose) installed.
*   Node.js and npm (optional, for running backend/frontend outside Docker or for development setup).
*   **GeoIP Database:** You need to download the `GeoLite2-City.mmdb` file from MaxMind.
    *   Go to [MaxMind GeoLite2 Download](https://dev.maxmind.com/geoip/downloads/geolite2/)
    *   Register for a free account.
    *   Download the `GeoLite2-City.mmdb.gz` file.
    *   Extract the `.gz` file to get `GeoLite2-City.mmdb`.
    *   Place this `GeoLite2-City.mmdb` file into the `autosec/data/geoip/` directory. **This step is crucial for GeoIP functionality.**

### Setup and Run (Local Development with Docker Compose)

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url> autosec
    cd autosec
    ```

2.  **Prepare Environment Variables:**
    Create a `.env` file in the `autosec/backend/` directory by copying from `.env.example`:
    ```bash
    cp backend/.env.example backend/.env
    ```
    You can keep the default values in `.env` for local development.

3.  **Download GeoIP Database:**
    Ensure you have downloaded `GeoLite2-City.mmdb` and placed it in `autosec/data/geoip/`. Create the `geoip` directory if it doesn't exist.

4.  **Build and Run with Docker Compose:**
    Navigate to the root `autosec/` directory and run:
    ```bash
    docker compose up --build -d
    ```
    This command will:
    *   Build the Docker images for the frontend and backend.
    *   Start PostgreSQL, MongoDB, RabbitMQ, Backend, and Frontend services.
    *   Initialize the PostgreSQL database schema using `database/postgres/init.sql`.

5.  **Access the Application:**
    *   **Frontend:** Open your web browser and go to `http://localhost:3000`
    *   **Backend API:** `http://localhost:8080/api` (for direct testing)
    *   **RabbitMQ Management UI:** `http://localhost:15672` (Login with guest/guest)

### Testing Log Ingestion

You can manually send logs to the backend using `curl` or Postman/Insomnia:

```bash
curl -X POST \
  http://localhost:8080/api/logs \
  -H 'Content-Type: application/json' \
  -d '{
    "level": "info",
    "source": "firewall",
    "event_type": "connection_attempt",
    "message": "Connection attempt from 192.0.2.1 to port 8080 blocked by firewall rule.",
    "ip_address": "192.0.2.1",
    "metadata": {
      "protocol": "TCP",
      "port": 8080,
      "action": "DENY"
    }
  }'
```
You can also try with an IP that has GeoIP data (e.g., a public IP like `8.8.8.8` or `203.0.113.1`):
```bash
curl -X POST \
  http://localhost:8080/api/logs \
  -H 'Content-Type: application/json' \
  -d '{
    "level": "warn",
    "source": "web_app",
    "event_type": "login_failure",
    "message": "Failed login attempt for user admin from IP 203.0.113.1",
    "ip_address": "203.0.113.1",
    "user_id": "admin"
  }'
```
After sending logs, navigate to the "Telemetry Logs" page in the frontend to see them appear.

### Stopping the Application

To stop all services and remove containers, networks, and volumes created by `docker compose`:
```bash
docker compose down -v
```
The `-v` flag removes the named volumes, which is useful for a clean slate, but will delete your database data. If you want to keep data, omit `-v`.

## Project Structure

*   `autosec/frontend/`: React.js application for the user interface.
*   `autosec/backend/`: Node.js/Express.js application for API services.
*   `autosec/database/`: Database initialization scripts and documentation.
    *   `postgres/`: PostgreSQL schema.
    *   `mongo/`: MongoDB notes.
*   `autosec/data/`: External data, e.g., GeoIP database.
*   `autosec/docker-compose.yml`: Orchestrates all services for local development.

## Future Enhancements (Conceptual)

This demo provides a foundational implementation. Future enhancements would include:

*   **Full Behavioral Analysis Engine:** Implement AI/ML models for UEBA and NBA.
*   **Advanced Enforcement:** Real integrations with firewalls (e.g., Palo Alto, Cisco, iptables) and SDN controllers.
*   **Threat Intelligence Integration:** Automated fetching and processing of external threat feeds.
*   **Incident Response Playbooks:** Automated actions and workflows for detected threats.
*   **Attack Surface Management:** Automated port scanning, vulnerability scanner integration, unused asset identification.
*   **Least Privilege Monitoring:** Deeper integration with IAM/PAM systems.
*   **User Authentication & Authorization:** Implement robust user management and role-based access control.
*   **Comprehensive Reporting & Analytics:** Advanced dashboards and customizable reports.
*   **Scalability & High Availability:** Production deployment on Kubernetes with horizontal scaling, load balancing, and redundancy.

---
```
