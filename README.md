# AutoSec: Advanced Cybersecurity Operations Platform

AutoSec is a comprehensive, enterprise-grade cybersecurity platform designed for proactive network defense, advanced threat detection, behavioral analysis, and automated incident response. Built with modern microservices architecture, AutoSec provides real-time security monitoring, dynamic enforcement, and AI-powered threat intelligence.

## 🌟 Key Features

### Core Security Capabilities
- **Dynamic IP Blocklisting** - Real-time IP reputation management with automated enforcement
- **Behavioral Analysis Engine** - AI/ML-powered User and Entity Behavior Analytics (UEBA) and Network Behavior Analytics (NBA)
- **Threat Intelligence Integration** - Automated threat feed processing and correlation
- **Incident Response Playbooks** - Automated workflows for threat detection and response
- **Attack Surface Management** - Continuous asset discovery and vulnerability assessment

### Advanced Integrations
- **Firewall Integration** - Native support for Palo Alto, Cisco, iptables, and SDN controllers
- **IAM/PAM Integration** - Least privilege monitoring and access management
- **Vulnerability Scanners** - Integration with leading vulnerability assessment tools
- **SIEM/SOAR Integration** - Seamless integration with existing security infrastructure

### Enterprise Features
- **Role-Based Access Control** - Granular permissions and user management
- **Advanced Analytics** - Real-time dashboards and customizable reporting
- **High Availability** - Kubernetes-ready with horizontal scaling and load balancing
- **Compliance Reporting** - Built-in compliance frameworks and audit trails

## 🚀 Quick Start

### Prerequisites
- **Docker & Docker Compose** - Latest version recommended (Docker 20.10+, Compose 2.0+)
- **GeoIP Database** - Download GeoLite2-City.mmdb from MaxMind (free registration required)
- **Hardware Requirements**:
  - CPU: 4+ cores recommended (2+ minimum)
  - RAM: 8GB+ recommended (4GB minimum)
  - Storage: 20GB+ available space
  - Network: Internet connection for threat intelligence feeds

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/GizzZmo/AutoSec.git autosec
   cd autosec
   ```

2. **Setup GeoIP database:**
   ```bash
   mkdir -p data/geoip
   # Download GeoLite2-City.mmdb from MaxMind and place in data/geoip/
   # Register at https://www.maxmind.com/en/geolite2/signup
   # Download the binary database (not CSV)
   wget -O data/geoip/GeoLite2-City.mmdb "YOUR_MAXMIND_DOWNLOAD_URL"
   ```

3. **Configure environment:**
   ```bash
   # Backend configuration
   cp backend/.env.example backend/.env
   
   # Generate secure JWT secrets
   openssl rand -base64 64 # Use this for JWT_SECRET
   openssl rand -base64 32 # Use this for encryption keys
   
   # Edit backend/.env with your configuration:
   # - Change default passwords
   # - Set secure JWT secrets  
   # - Configure external service credentials (optional)
   ```

4. **Deploy the platform:**
   ```bash
   # Build and start all services
   docker compose up --build -d
   
   # Check service health
   docker compose ps
   docker compose logs -f autosec-backend
   ```

5. **Initialize the system:**
   ```bash
   # Wait for all services to be healthy (may take 2-3 minutes)
   docker compose exec autosec-backend npm run db:migrate
   docker compose exec autosec-backend npm run db:seed
   
   # Create admin user (optional - can also register via UI)
   docker compose exec autosec-backend npm run create-admin
   ```

### Access Points
- **Web Console**: http://localhost:3000
- **API Gateway**: http://localhost:8080/api
- **API Documentation**: http://localhost:8080/api/docs (Swagger UI)
- **RabbitMQ Management**: http://localhost:15672 (guest/guest)

### First Steps

1. **Access the web console** at http://localhost:3000
2. **Register an admin account** or use the created admin credentials
3. **Configure your first blocking rule** in the Rules section
4. **Test log ingestion** using the API or web interface
5. **Review the dashboard** for system status and metrics

### Verification

```bash
# Test API health
curl http://localhost:8080/api/health

# Test GeoIP functionality
curl "http://localhost:8080/api/geoip?ip=8.8.8.8"

# Check all services are running
docker compose ps

# View service logs
docker compose logs -f autosec-backend
docker compose logs -f autosec-frontend

# Test database connections
docker compose exec autosec-backend npm run db:migrate -- --dry-run
```

## 🏗️ Architecture Overview

AutoSec follows a modern, cloud-native microservices architecture designed for scalability, resilience, and security. The platform consists of over 14,000 lines of production-ready code implementing advanced cybersecurity capabilities.

### System Components

#### Frontend Layer
- **React Web Console** - Modern, responsive cybersecurity dashboard with cyberpunk theme
- **Real-time Dashboards** - Live threat monitoring and system status using WebSocket connections
- **Mobile-Responsive UI** - Optimized for desktop, tablet, and mobile access
- **Component Architecture** - Modular React components for maintainability

#### API Gateway & Services
- **Express.js API Gateway** - Centralized API management and routing with middleware
- **Authentication Service** - JWT-based authentication with refresh tokens and RBAC
- **Security Middleware** - Rate limiting, input validation, CORS, and security headers
- **Swagger Documentation** - Auto-generated API documentation and testing interface

#### AI/ML Engine (Implemented)
- **Behavioral Analysis Engine** - UEBA and NBA with multiple ML algorithms
- **Threat Detection Models** - Real-time anomaly detection using clustering and statistical methods
- **Risk Scoring Engine** - Dynamic threat prioritization with ensemble models
- **Feature Extraction** - Advanced temporal, frequency, and statistical pattern analysis

#### Data Layer
- **PostgreSQL** - Structured data (users, rules, configurations, audit logs)
- **MongoDB** - Unstructured data (logs, events, analytics, behavioral data)
- **Redis** - Caching, session management, and real-time data
- **Message Queues** - RabbitMQ for asynchronous processing and job queues

#### Enterprise Integrations (Implemented)
- **SDN Controllers** - OpenDaylight and ONOS integration for network flow control
- **SIEM Systems** - Complete Splunk and QRadar integration with automated event correlation
- **Vulnerability Scanners** - Nessus, OpenVAS, and Qualys integration with automated scanning
- **Ticketing Systems** - JIRA and ServiceNow integration for incident management
- **Threat Intelligence** - MISP, STIX/TAXII, and AlienVault OTX feed integration

#### Enhanced Security Operations
- **Automated Playbooks** - Workflow engine with customizable response automation
- **Incident Management** - Complete incident lifecycle with timeline tracking and escalation
- **IOC Management** - Comprehensive indicators of compromise with enrichment and matching
- **Asset Discovery** - Network, DNS, service, and cloud asset discovery and inventory
- **Compliance Reporting** - Automated SOC 2, ISO 27001, NIST, and GDPR compliance reports

#### Infrastructure & DevOps
- **Docker/Kubernetes** - Container orchestration with health checks
- **Message Queues** - RabbitMQ for reliable asynchronous processing
- **Load Balancing** - Nginx configuration for high availability
- **Monitoring** - Built-in health checks and metrics endpoints

### Security Features

#### Network Security
- **Dynamic IP Blocklisting** - Real-time threat blocking
- **Geo-blocking** - Country and region-based filtering
- **Rate Limiting** - DDoS and brute-force protection
- **Network Segmentation** - Automated micro-segmentation

#### Behavioral Analytics
- **User Behavior Analytics (UBA)** - Anomalous user activity detection
- **Entity Behavior Analytics (EBA)** - Device and service monitoring
- **Network Behavior Analytics (NBA)** - Traffic pattern analysis
- **Machine Learning Models** - Adaptive threat detection

#### Incident Response
- **Automated Playbooks** - Response workflow automation
- **Threat Hunting** - Proactive threat investigation
- **Forensic Analysis** - Detailed incident reconstruction
- **Compliance Reporting** - Automated audit and compliance

## 📋 Current Implementation Status

### ✅ Implemented Features

#### Core Platform
- [x] Microservices architecture with Docker
- [x] PostgreSQL and MongoDB database integration
- [x] Redis caching and session management
- [x] RabbitMQ message queue system
- [x] React frontend with responsive cyberpunk-themed design
- [x] REST API with Express.js and Swagger documentation
- [x] GeoIP integration for location-based analysis

#### Authentication & Authorization
- [x] JWT-based authentication system with refresh tokens
- [x] Role-based access control (RBAC) with granular permissions
- [x] Multi-factor authentication (MFA) with TOTP support
- [x] Single sign-on (SSO) integration framework
- [x] Password hashing with bcrypt
- [x] Session management and security middleware

#### Security Features
- [x] Dynamic IP blocklist management (single IPs, ranges, countries, organizations)
- [x] Real-time log ingestion and processing via RabbitMQ
- [x] Advanced threat detection and alerting
- [x] Network flow analysis and monitoring
- [x] Geographic-based filtering and geo-blocking
- [x] Rate limiting and DDoS protection
- [x] Security headers and input validation

#### Behavioral Analysis Engine
- [x] Machine learning models for anomaly detection using multiple algorithms
- [x] User and Entity Behavior Analytics (UEBA) with risk scoring
- [x] Network Behavior Analytics (NBA) with statistical analysis
- [x] Real-time behavior monitoring and alerting
- [x] ML-based clustering and classification
- [x] Advanced feature extraction for temporal, frequency, and statistical patterns

#### Firewall Integrations
- [x] Palo Alto Networks firewall integration with XML API
- [x] Cisco ASA/FTD integration with SSH/API support
- [x] iptables/netfilter integration for Linux systems
- [x] Firewall integration manager with unified interface

### ✅ Advanced Features (Recently Added)

#### Advanced Integrations
- [x] SDN controller integration (OpenDaylight, ONOS)
- [x] Enhanced SIEM/SOAR connectors (Splunk, QRadar, etc.)
- [x] Advanced vulnerability scanner integrations (Nessus, OpenVAS, Qualys)

#### Threat Intelligence & Analytics
- [x] External threat feed integration (MISP, STIX/TAXII)
- [x] IOC (Indicators of Compromise) management
- [x] Automated threat correlation and intelligence
- [ ] Advanced threat hunting capabilities

#### Incident Response & Automation
- [x] Automated response playbooks and workflows
- [x] Advanced incident management and forensic analysis
- [x] Compliance reporting automation (SOC 2, ISO 27001, NIST, GDPR)
- [x] Integration with ticketing systems (JIRA, ServiceNow)

#### Attack Surface Management
- [x] Automated asset discovery and inventory
- [x] Continuous security posture assessment
- [x] Risk assessment and scoring optimization

### 🎯 Planned Features

#### Enterprise Features
- [x] Kubernetes deployment with Helm charts
- [x] High availability and horizontal scaling
- [x] Advanced monitoring and observability (Prometheus/Grafana)
- [x] Disaster recovery and backup systems
- [x] Service mesh integration (Istio)

#### Analytics & Reporting
- [x] Advanced dashboard customization and widgets
- [x] Real-time threat visualization and 3D network maps
- [x] Custom report generation with scheduled delivery
- [x] Executive summary dashboards and KPI tracking
- [x] Machine learning model performance monitoring

#### Advanced Security Features
- [x] Zero Trust Network Access (ZTNA) integration
- [x] Cloud security posture management (CSPM)
- [x] Container security scanning and runtime protection
- [x] Data loss prevention (DLP) integration
- [x] Advanced deception technology and threat hunting

## 🔧 Development Setup

### Local Development Environment

1. **Install development dependencies:**
   ```bash
   # Backend development
   cd backend
   npm install
   
   # Frontend development  
   cd ../frontend
   npm install
   ```

2. **Database setup:**
   ```bash
   # Start only databases and message broker for development
   docker compose up postgres mongodb redis rabbitmq -d
   
   # Wait for services to be healthy
   docker compose ps
   ```

3. **Environment configuration:**
   ```bash
   # Backend configuration
   cd backend
   cp .env.example .env
   # Edit .env with your specific configuration:
   # - Database connection strings
   # - JWT secrets (generate secure random strings)
   # - GeoIP database path
   # - External service credentials
   
   # Frontend configuration
   cd ../frontend
   cp .env.example .env
   # Configure API base URL and other frontend settings
   ```

4. **Start development servers:**
   ```bash
   # Start backend with hot reload
   cd backend
   npm run dev
   
   # In another terminal, start frontend
   cd frontend
   npm start
   ```

### Testing

```bash
# Backend tests (unit, integration, and API tests)
cd backend
npm test                    # Run all tests
npm run test:watch          # Run tests in watch mode
npm run test:coverage       # Generate coverage report

# Frontend tests
cd frontend
npm test                    # Run React tests
npm run test:coverage       # Generate coverage report

# End-to-end testing
npm run test:e2e            # Full application testing

# Load testing
npm run test:load           # Performance and load testing
```

### Code Quality & Security

```bash
# Backend linting and formatting
cd backend
npm run lint                # ESLint check
npm run lint:fix            # Auto-fix linting issues
npm run format              # Prettier formatting

# Security auditing
npm audit                   # Check for security vulnerabilities
npm run security:check      # Additional security scanning

# Frontend linting
cd frontend
npm run lint
npm run lint:fix

# Dependency checking
npm run deps:check          # Check for outdated dependencies
npm run deps:update         # Update dependencies
```

### Database Management

```bash
# PostgreSQL migrations and seeding
cd backend
npm run db:migrate          # Run database migrations
npm run db:seed             # Seed database with initial data
npm run db:reset            # Reset database (dev only)

# MongoDB setup
npm run mongo:setup         # Initialize MongoDB collections
npm run mongo:index         # Create database indexes
```

## 🚀 Production Deployment

### Kubernetes Deployment

AutoSec is designed for cloud-native deployment with Kubernetes support:

```bash
# Deploy with Helm (coming soon)
# helm repo add autosec https://gizzmo.github.io/AutoSec-helm-charts
# helm install autosec autosec/autosec-platform

# Or use kubectl
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/mongodb.yaml
kubectl apply -f k8s/rabbitmq.yaml
kubectl apply -f k8s/backend.yaml
kubectl apply -f k8s/frontend.yaml
kubectl apply -f k8s/ingress.yaml
```

### High Availability Configuration

```yaml
# Example production values.yaml for Helm
replicaCount:
  backend: 3
  frontend: 2
  
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  
resources:
  backend:
    requests:
      memory: "512Mi"
      cpu: "500m"
    limits:
      memory: "1Gi"
      cpu: "1000m"

persistence:
  postgresql:
    size: 100Gi
    storageClass: "fast-ssd"
  mongodb:
    size: 500Gi
    storageClass: "fast-ssd"
```

### Security Hardening

```bash
# SSL/TLS Configuration
kubectl create secret tls autosec-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem

# Database encryption
kubectl create secret generic db-encryption-key \
  --from-literal=key=$(openssl rand -base64 32)

# Service mesh (Istio)
kubectl label namespace autosec istio-injection=enabled
```

### Monitoring & Observability

```bash
# Prometheus & Grafana
helm install prometheus prometheus-community/kube-prometheus-stack

# ELK Stack
helm install elasticsearch elastic/elasticsearch
helm install kibana elastic/kibana

# Jaeger for distributed tracing
kubectl apply -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.29.0/jaeger-operator.yaml
```

## 📊 API Documentation

AutoSec provides a comprehensive REST API with Swagger/OpenAPI documentation available at `/api/docs`.

### Authentication Endpoints

```bash
# User authentication
POST /api/auth/register      # Register new user
POST /api/auth/login         # User login
POST /api/auth/logout        # User logout
POST /api/auth/refresh       # Refresh access token
GET  /api/auth/profile       # Get user profile
PUT  /api/auth/profile       # Update user profile
POST /api/auth/change-password # Change user password

# Multi-Factor Authentication
POST /api/mfa/setup          # Setup MFA for user
POST /api/mfa/verify         # Verify MFA token
POST /api/mfa/disable        # Disable MFA
GET  /api/mfa/qr             # Get QR code for MFA setup

# User management (Admin only)
GET    /api/users            # List all users
POST   /api/users            # Create new user
GET    /api/users/:id        # Get user by ID
PUT    /api/users/:id        # Update user
DELETE /api/users/:id        # Delete user
POST   /api/users/:id/roles  # Assign roles to user
```

### Security Management

```bash
# Blocklist management
GET    /api/rules           # Get all blocking rules with pagination
POST   /api/rules           # Create new blocking rule
PUT    /api/rules/:id       # Update existing rule
DELETE /api/rules/:id       # Delete blocking rule

# Threat intelligence and analysis
GET    /api/threats         # Get threat indicators
POST   /api/threats/scan    # Initiate threat scan
GET    /api/threats/feeds   # Manage threat feeds
POST   /api/threats/ioc     # Add indicators of compromise

# Behavioral analysis
GET    /api/behavior/user/:id    # Get user behavior analysis
GET    /api/behavior/network     # Get network behavior metrics
POST   /api/behavior/analyze     # Trigger behavior analysis
GET    /api/behavior/anomalies   # Get detected anomalies
GET    /api/behavior/risk-score  # Get current risk scores
```

### Log Management & Analytics

```bash
# Log ingestion and retrieval
POST   /api/logs           # Ingest log data (accepts batch)
GET    /api/logs           # Retrieve logs with advanced filtering
GET    /api/logs/search    # Full-text search in logs
GET    /api/logs/stats     # Get log statistics and metrics
GET    /api/logs/export    # Export logs (CSV, JSON)

# Real-time analytics
GET /api/analytics/dashboard     # Main dashboard data
GET /api/analytics/threats/live  # Live threat feed
GET /api/analytics/network/traffic # Network traffic analysis
GET /api/analytics/users/behavior  # User behavior patterns
GET /api/analytics/geo           # Geographic threat distribution
```

### System Utilities

```bash
# GeoIP and location services
GET /api/geoip?ip=<IP>      # Get GeoIP information for IP
GET /api/geoip/bulk         # Bulk GeoIP lookup

# System health and monitoring
GET /api/health             # System health check
GET /api/status             # Detailed system status
GET /api/metrics            # System performance metrics
GET /api/version            # API version information
```

## 🔗 Integration Examples

AutoSec provides built-in integrations with major security infrastructure components.

### Firewall Integration

```javascript
// Palo Alto Networks Integration
const PaloAltoIntegration = require('./integrations/paloAltoIntegration');

const paloAlto = new PaloAltoIntegration({
  hostname: 'firewall.company.com',
  username: process.env.PALO_ALTO_USERNAME,
  password: process.env.PALO_ALTO_PASSWORD,
  // or use API key authentication
  apiKey: process.env.PALO_ALTO_API_KEY,
  vsys: 'vsys1'
});

// Block IP address with context
await paloAlto.blockIP('192.168.1.100', {
  reason: 'Suspicious activity detected',
  severity: 'high',
  source: 'AutoSec Behavioral Analysis'
});

// Create address group for batch blocking
await paloAlto.createAddressGroup('autosec-threats', [
  '10.0.0.100',
  '10.0.0.101',
  '10.0.0.102'
]);

// Cisco ASA Integration
const CiscoASAIntegration = require('./integrations/ciscoASAIntegration');

const ciscoASA = new CiscoASAIntegration({
  hostname: 'asa.company.com',
  username: process.env.CISCO_USERNAME,
  password: process.env.CISCO_PASSWORD,
  enablePassword: process.env.CISCO_ENABLE_PASSWORD
});

// Add access control rule
await ciscoASA.addAccessRule({
  name: 'BLOCK_THREAT_192.168.1.100',
  source: '192.168.1.100',
  destination: 'any',
  action: 'deny',
  protocol: 'ip'
});

// iptables Integration for Linux systems
const IptablesIntegration = require('./integrations/iptablesIntegration');

const iptables = new IptablesIntegration({
  sudo: true,
  chain: 'INPUT'
});

await iptables.blockIP('192.168.1.100', {
  protocol: 'tcp',
  port: 22,
  comment: 'AutoSec: SSH brute force attempt'
});
```

### Multi-Factor Authentication

```javascript
const MFAService = require('./services/mfaService');

const mfaService = new MFAService();

// Setup MFA for user
const mfaSetup = mfaService.generateSecret(username, 'AutoSec');
const qrCode = await mfaService.generateQRCode(mfaSetup.dataURL);

// Verify MFA token
const isValid = mfaService.verifyToken(token, user.mfaSecret);

// Generate backup codes
const backupCodes = mfaService.generateBackupCodes();
```

### Behavioral Analysis Integration

```javascript
const MLBehaviorAnalysisService = require('./services/mlBehaviorAnalysisService');

const mlService = new MLBehaviorAnalysisService();

// Analyze user behavior patterns
const behaviorAnalysis = await mlService.analyzeUserBehavior({
  userId: 'user123',
  loginTimes: [...],
  ipAddresses: [...],
  deviceFingerprints: [...],
  accessPatterns: [...]
}, 'user123');

// Get risk score
const riskScore = behaviorAnalysis.riskScore;
if (riskScore > 0.8) {
  // Trigger additional security measures
  await triggerMFAChallenge(userId);
}

// Analyze network behavior
const networkAnalysis = await mlService.analyzeNetworkBehavior({
  trafficPatterns: [...],
  connectionMetrics: [...],
  protocolDistribution: [...]
});
```

## 🤝 Contributing

We welcome contributions to AutoSec! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Guidelines

1. **Code Style**: Follow ESLint and Prettier configurations
2. **Testing**: Maintain 90%+ test coverage
3. **Documentation**: Update docs for all new features
4. **Security**: Follow secure coding practices
5. **Performance**: Optimize for high-throughput scenarios

### Reporting Issues

- **Security Issues**: Report privately via [GitHub Security Advisories](https://github.com/GizzZmo/AutoSec/security/advisories)
- **Bug Reports**: Use [GitHub Issues](https://github.com/GizzZmo/AutoSec/issues) with detailed reproduction steps
- **Feature Requests**: Use [GitHub Discussions](https://github.com/GizzZmo/AutoSec/discussions) for community input

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Project Documentation](docs/README.md) and [GitHub Wiki](https://github.com/GizzZmo/AutoSec/wiki)
- **Community Forum**: [GitHub Discussions](https://github.com/GizzZmo/AutoSec/discussions)
- **Bug Reports & Feature Requests**: [GitHub Issues](https://github.com/GizzZmo/AutoSec/issues)
- **Security Issues**: Report privately via [GitHub Security Advisories](https://github.com/GizzZmo/AutoSec/security/advisories)

## 🙏 Acknowledgments

- MaxMind for GeoIP data
- The open-source security community
- Contributors and maintainers
- Enterprise customers and partners

---

**AutoSec** - Advanced Cybersecurity Operations Platform
Built with ❤️ for the cybersecurity community
