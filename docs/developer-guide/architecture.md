# AutoSec Architecture Overview

This document provides a comprehensive overview of AutoSec's system architecture, design patterns, and technical implementation.

## 🏗️ System Architecture

### High-Level Architecture

AutoSec follows a modern microservices architecture designed for scalability, reliability, and maintainability:

```
┌─────────────────────────────────────────────────────────────┐
│                    External Integrations                    │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Firewalls     │   Threat Feeds  │   Identity Providers    │
│ • Palo Alto     │ • MISP          │ • Active Directory      │
│ • Cisco ASA     │ • STIX/TAXII    │ • LDAP                  │
│ • iptables      │ • Commercial    │ • SAML/OAuth            │
└─────────────────┴─────────────────┴─────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│                     API Gateway Layer                        │
│  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Nginx       │ │   Load Balancer │ │   Rate Limiter  │   │
│  │   Proxy       │ │                 │ │                 │   │
│  └───────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────▼─────────────────────────────────┘
┌─────────────────────────────▼─────────────────────────────────┐
│                   Application Layer                          │
│  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   React       │ │   Express.js    │ │   WebSocket     │   │
│  │   Frontend    │ │   API Server    │ │   Server        │   │
│  └───────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────▼─────────────────────────────────┘
┌─────────────────────────────▼─────────────────────────────────┐
│                    Business Logic Layer                      │
│  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Auth        │ │   Threat        │ │   Behavior      │   │
│  │   Service     │ │   Detection     │ │   Analysis      │   │
│  └───────────────┘ └─────────────────┘ └─────────────────┘   │
│  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Rule        │ │   Integration   │ │   ML Engine     │   │
│  │   Engine      │ │   Manager       │ │                 │   │
│  └───────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────▼─────────────────────────────────┘
┌─────────────────────────────▼─────────────────────────────────┐
│                     Data Access Layer                        │
│  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Sequelize   │ │   Mongoose      │ │   Redis Client  │   │
│  │   (PostgreSQL)│ │   (MongoDB)     │ │                 │   │
│  └───────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────▼─────────────────────────────────┘
┌─────────────────────────────▼─────────────────────────────────┐
│                      Data Storage Layer                      │
│  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │  PostgreSQL   │ │    MongoDB      │ │     Redis       │   │
│  │  (Structured  │ │  (Unstructured  │ │   (Caching)     │   │
│  │     Data)     │ │      Data)      │ │                 │   │
│  └───────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                    Infrastructure Layer                        │
│  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐     │
│  │    Docker     │ │   RabbitMQ      │ │   Monitoring    │     │
│  │  Containers   │ │  Message Queue  │ │     Stack       │     │
│  └───────────────┘ └─────────────────┘ └─────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Component Architecture

### Frontend Architecture

#### React Application Structure
```
frontend/src/
├── components/           # Reusable UI components
│   ├── common/          # Common components (Button, Modal, etc.)
│   ├── forms/           # Form components
│   ├── charts/          # Chart and visualization components
│   └── layout/          # Layout components (Header, Sidebar)
├── pages/               # Page components
│   ├── Dashboard/       # Dashboard page
│   ├── Blocklist/       # Rules management
│   ├── Logs/            # Log viewer
│   └── Analytics/       # Analytics dashboard
├── services/            # API service layer
│   ├── api.js           # Base API client
│   ├── auth.js          # Authentication services
│   └── websocket.js     # WebSocket client
├── hooks/               # Custom React hooks
├── utils/               # Utility functions
└── styles/              # CSS and styling
```

#### Component Design Patterns
```javascript
// Container/Presentational Pattern
const DashboardContainer = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData().then(setData).finally(() => setLoading(false));
  }, []);

  return (
    <DashboardPresentation 
      data={data} 
      loading={loading} 
      onRefresh={fetchDashboardData}
    />
  );
};

// Custom Hooks Pattern
const useSecurityData = (endpoint) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.get(endpoint)
      .then(setData)
      .catch(setError)
      .finally(() => setLoading(false));
  }, [endpoint]);

  return { data, loading, error };
};
```

### Backend Architecture

#### Service Layer Architecture
```
backend/src/
├── app.js               # Express application setup
├── server.js            # Server entry point
├── config/              # Configuration files
│   ├── database.js      # Database configurations
│   ├── redis.js         # Redis configuration
│   └── logger.js        # Logging configuration
├── controllers/         # Request handlers
│   ├── authController.js
│   ├── ruleController.js
│   └── behaviorController.js
├── middleware/          # Express middleware
│   ├── auth.js          # Authentication middleware
│   ├── validation.js    # Input validation
│   └── security.js      # Security middleware
├── models/              # Data models
│   ├── User.js          # User model (Sequelize)
│   ├── Rule.js          # Rule model (Sequelize)
│   └── Log.js           # Log model (Mongoose)
├── routes/              # Route definitions
├── services/            # Business logic services
│   ├── authService.js
│   ├── threatService.js
│   └── mlService.js
├── integrations/        # External integrations
│   ├── firewallManager.js
│   └── threatIntel.js
└── utils/               # Utility functions
```

#### Service Layer Pattern
```javascript
// Service class example
class ThreatDetectionService {
  constructor(dependencies) {
    this.mlService = dependencies.mlService;
    this.ruleEngine = dependencies.ruleEngine;
    this.logger = dependencies.logger;
  }

  async analyzeThreat(logEntry) {
    try {
      // ML-based analysis
      const mlResult = await this.mlService.analyze(logEntry);
      
      // Rule-based analysis
      const ruleResult = await this.ruleEngine.evaluate(logEntry);
      
      // Combine results
      const threat = this.combineThreatScores(mlResult, ruleResult);
      
      if (threat.score > 0.8) {
        await this.handleHighRiskThreat(threat);
      }
      
      return threat;
    } catch (error) {
      this.logger.error('Threat analysis failed:', error);
      throw error;
    }
  }
}
```

### Data Architecture

#### Multi-Database Strategy

**PostgreSQL (Structured Data)**
- User accounts and profiles
- Security rules and policies
- System configuration
- Audit logs

```sql
-- User table schema
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    mfa_secret VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Rules table schema
CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    action VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    reason TEXT,
    created_by UUID REFERENCES users(id),
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**MongoDB (Unstructured Data)**
- Security logs and events
- Behavioral analysis data
- Threat intelligence feeds
- Machine learning models

```javascript
// Log schema (Mongoose)
const logSchema = new mongoose.Schema({
  timestamp: { type: Date, required: true, index: true },
  source_ip: { type: String, required: true, index: true },
  destination_ip: { type: String, required: true },
  protocol: { type: String, required: true },
  action: { type: String, required: true },
  geo_info: {
    country: String,
    city: String,
    latitude: Number,
    longitude: Number
  },
  risk_score: { type: Number, min: 0, max: 1 },
  metadata: mongoose.Schema.Types.Mixed,
  processed: { type: Boolean, default: false }
}, {
  timeseries: {
    timeField: 'timestamp',
    metaField: 'metadata',
    granularity: 'minutes'
  }
});

// Behavioral analysis schema
const behaviorSchema = new mongoose.Schema({
  user_id: { type: String, required: true, index: true },
  analysis_date: { type: Date, required: true },
  patterns: {
    login_times: [Number],
    ip_addresses: [String],
    device_fingerprints: [String],
    access_patterns: [Object]
  },
  anomalies: [{
    type: String,
    severity: String,
    score: Number,
    description: String,
    timestamp: Date
  }],
  risk_score: { type: Number, min: 0, max: 1 }
});
```

**Redis (Caching and Sessions)**
- Session management
- Rate limiting counters
- Real-time threat feeds
- Temporary data caching

```javascript
// Redis usage patterns
class CacheService {
  constructor(redisClient) {
    this.redis = redisClient;
  }

  // Session management
  async storeSession(sessionId, data, ttl = 3600) {
    await this.redis.setex(`session:${sessionId}`, ttl, JSON.stringify(data));
  }

  // Rate limiting
  async checkRateLimit(key, limit, window) {
    const current = await this.redis.incr(key);
    if (current === 1) {
      await this.redis.expire(key, window);
    }
    return current <= limit;
  }

  // Threat feed caching
  async cacheThreatFeed(feedName, data, ttl = 300) {
    await this.redis.setex(`threat:${feedName}`, ttl, JSON.stringify(data));
  }
}
```

## 🤖 Machine Learning Architecture

### ML Pipeline Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data          │    │   Feature       │    │   Model         │
│   Ingestion     │───▶│   Engineering   │───▶│   Training      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Raw Logs      │    │   Features      │    │   Trained       │
│   • Network     │    │   • Temporal    │    │   Models        │
│   • System      │    │   • Statistical │    │   • Clustering  │
│   • Security    │    │   • Behavioral  │    │   • Anomaly Det │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
                              ┌─────────────────┐    ┌─────────────────┐
                              │   Model         │    │   Real-time     │
                              │   Evaluation    │◀───│   Inference     │
                              │                 │    │                 │
                              └─────────────────┘    └─────────────────┘
```

### Behavioral Analysis Engine

```javascript
class BehaviorAnalysisEngine {
  constructor() {
    this.algorithms = {
      clustering: new KMeansClusterer(),
      anomalyDetection: new IsolationForest(),
      statisticalAnalysis: new StatisticalAnalyzer(),
      temporalAnalysis: new TemporalAnalyzer()
    };
  }

  async analyzeUserBehavior(userId, timeRange) {
    // Collect user data
    const userData = await this.collectUserData(userId, timeRange);
    
    // Feature extraction
    const features = this.extractFeatures(userData);
    
    // Apply multiple ML algorithms
    const results = await Promise.all([
      this.algorithms.clustering.analyze(features),
      this.algorithms.anomalyDetection.detect(features),
      this.algorithms.statisticalAnalysis.analyze(features),
      this.algorithms.temporalAnalysis.analyze(features)
    ]);

    // Combine results using ensemble method
    const riskScore = this.calculateEnsembleScore(results);
    const anomalies = this.identifyAnomalies(results);

    return {
      userId,
      riskScore,
      anomalies,
      confidence: this.calculateConfidence(results),
      timestamp: new Date()
    };
  }

  extractFeatures(userData) {
    return {
      temporal: this.extractTemporalFeatures(userData),
      frequency: this.extractFrequencyFeatures(userData),
      statistical: this.extractStatisticalFeatures(userData),
      behavioral: this.extractBehavioralFeatures(userData)
    };
  }
}
```

## 🔗 Integration Architecture

### Firewall Integration Framework

```javascript
class FirewallIntegrationManager {
  constructor() {
    this.integrations = new Map();
    this.loadIntegrations();
  }

  loadIntegrations() {
    this.integrations.set('paloalto', new PaloAltoIntegration());
    this.integrations.set('cisco', new CiscoASAIntegration());
    this.integrations.set('iptables', new IptablesIntegration());
  }

  async blockIP(ipAddress, firewallType, options = {}) {
    const integration = this.integrations.get(firewallType);
    if (!integration) {
      throw new Error(`Unsupported firewall type: ${firewallType}`);
    }

    return await integration.blockIP(ipAddress, options);
  }
}

// Base integration class
class BaseFirewallIntegration {
  constructor(config) {
    this.config = config;
    this.validateConfig();
  }

  async blockIP(ipAddress, options) {
    throw new Error('blockIP method must be implemented');
  }

  async unblockIP(ipAddress, options) {
    throw new Error('unblockIP method must be implemented');
  }

  validateConfig() {
    throw new Error('validateConfig method must be implemented');
  }
}
```

### Message Queue Architecture

```javascript
// RabbitMQ message processing
class MessageProcessor {
  constructor(rabbitmqUrl) {
    this.connection = null;
    this.channel = null;
    this.processors = new Map();
    this.init(rabbitmqUrl);
  }

  async init(url) {
    this.connection = await amqp.connect(url);
    this.channel = await this.connection.createChannel();
    
    // Define queues
    await this.setupQueues();
    
    // Register processors
    this.registerProcessors();
  }

  async setupQueues() {
    const queues = [
      'log_processing',
      'threat_analysis',
      'behavior_analysis',
      'firewall_actions'
    ];

    for (const queue of queues) {
      await this.channel.assertQueue(queue, { durable: true });
    }
  }

  registerProcessors() {
    this.processors.set('log_processing', new LogProcessor());
    this.processors.set('threat_analysis', new ThreatAnalysisProcessor());
    this.processors.set('behavior_analysis', new BehaviorAnalysisProcessor());
    this.processors.set('firewall_actions', new FirewallActionProcessor());
  }

  async startProcessing() {
    for (const [queueName, processor] of this.processors) {
      await this.channel.consume(queueName, async (msg) => {
        try {
          const data = JSON.parse(msg.content.toString());
          await processor.process(data);
          this.channel.ack(msg);
        } catch (error) {
          console.error(`Error processing message from ${queueName}:`, error);
          this.channel.nack(msg, false, false); // Dead letter queue
        }
      });
    }
  }
}
```

## 📊 Monitoring and Observability

### Application Monitoring

```javascript
// Metrics collection
class MetricsCollector {
  constructor() {
    this.metrics = {
      httpRequests: new Map(),
      dbConnections: new Map(),
      threatDetections: new Map(),
      systemHealth: new Map()
    };
    
    this.startCollection();
  }

  recordHttpRequest(method, path, statusCode, duration) {
    const key = `${method}:${path}`;
    const current = this.metrics.httpRequests.get(key) || {
      count: 0,
      totalDuration: 0,
      statusCodes: new Map()
    };

    current.count++;
    current.totalDuration += duration;
    current.statusCodes.set(statusCode, 
      (current.statusCodes.get(statusCode) || 0) + 1);

    this.metrics.httpRequests.set(key, current);
  }

  getSystemHealth() {
    return {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      connections: this.getActiveConnections(),
      timestamp: new Date()
    };
  }
}

// Health check middleware
const healthCheck = async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date(),
    services: {}
  };

  try {
    // Check database connections
    health.services.postgres = await checkPostgresHealth();
    health.services.mongodb = await checkMongoHealth();
    health.services.redis = await checkRedisHealth();
    health.services.rabbitmq = await checkRabbitMQHealth();

    // Check external integrations
    health.services.geoip = await checkGeoIPHealth();

    const allHealthy = Object.values(health.services)
      .every(status => status === 'healthy');

    if (!allHealthy) {
      health.status = 'degraded';
      return res.status(503).json(health);
    }

    res.json(health);
  } catch (error) {
    health.status = 'unhealthy';
    health.error = error.message;
    res.status(503).json(health);
  }
};
```

## 🚀 Deployment Architecture

### Container Architecture

```dockerfile
# Multi-stage Dockerfile for backend
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS production
RUN addgroup -g 1001 -S nodejs
RUN adduser -S autosec -u 1001

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --chown=autosec:nodejs . .

USER autosec
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["node", "src/server.js"]
```

### Kubernetes Deployment

```yaml
# Backend deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autosec-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: autosec-backend
  template:
    metadata:
      labels:
        app: autosec-backend
    spec:
      containers:
      - name: backend
        image: autosec/backend:latest
        ports:
        - containerPort: 8080
        env:
        - name: NODE_ENV
          value: "production"
        - name: PG_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: postgres-password
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## 🔧 Configuration Management

### Environment-based Configuration

```javascript
// Configuration factory
class ConfigurationManager {
  constructor() {
    this.config = this.loadConfiguration();
    this.validateConfiguration();
  }

  loadConfiguration() {
    const env = process.env.NODE_ENV || 'development';
    
    const baseConfig = {
      app: {
        name: 'AutoSec',
        version: process.env.npm_package_version,
        port: parseInt(process.env.PORT, 10) || 8080
      },
      database: {
        postgres: {
          host: process.env.PG_HOST || 'localhost',
          port: parseInt(process.env.PG_PORT, 10) || 5432,
          database: process.env.PG_DATABASE || 'autosec_db',
          username: process.env.PG_USER || 'autosec_user',
          password: process.env.PG_PASSWORD || 'autosec_password'
        },
        mongodb: {
          uri: process.env.MONGO_URI || 'mongodb://localhost:27017/autosec_logs'
        },
        redis: {
          url: process.env.REDIS_URL || 'redis://localhost:6379'
        }
      },
      security: {
        jwtSecret: process.env.JWT_SECRET,
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
        bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12
      }
    };

    // Environment-specific overrides
    const envConfigs = {
      development: {
        logging: { level: 'debug' },
        security: { jwtSecret: 'dev-secret-key' }
      },
      production: {
        logging: { level: 'info' },
        security: { 
          requireHttps: true,
          trustProxy: true
        }
      }
    };

    return { ...baseConfig, ...(envConfigs[env] || {}) };
  }

  validateConfiguration() {
    const required = [
      'security.jwtSecret',
      'database.postgres.password'
    ];

    for (const path of required) {
      if (!this.getConfigValue(path)) {
        throw new Error(`Required configuration missing: ${path}`);
      }
    }
  }

  getConfigValue(path) {
    return path.split('.').reduce((obj, key) => obj?.[key], this.config);
  }
}
```

This architecture provides a solid foundation for AutoSec's scalability, maintainability, and security requirements while enabling future enhancements and integrations.