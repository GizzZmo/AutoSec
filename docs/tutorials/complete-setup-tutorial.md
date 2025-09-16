# AutoSec Complete Tutorial: From Setup to Advanced Usage

This comprehensive tutorial will guide you through setting up AutoSec, configuring integrations, and using its advanced features for cybersecurity operations.

## 🎯 Tutorial Overview

By the end of this tutorial, you will have:
- ✅ A fully functional AutoSec installation
- ✅ Configured firewall integrations
- ✅ Set up behavioral analysis and monitoring
- ✅ Created custom security rules and policies
- ✅ Deployed threat detection workflows
- ✅ Configured reporting and dashboards

**Time Required:** 2-3 hours  
**Skill Level:** Intermediate  
**Prerequisites:** Basic Linux/Docker knowledge, network security concepts

## 📚 Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Initial Configuration](#2-initial-configuration)
3. [User and Role Management](#3-user-and-role-management)
4. [Firewall Integration](#4-firewall-integration)
5. [Threat Detection Setup](#5-threat-detection-setup)
6. [Behavioral Analysis Configuration](#6-behavioral-analysis-configuration)
7. [Dashboard Customization](#7-dashboard-customization)
8. [API Integration](#8-api-integration)
9. [Advanced Security Policies](#9-advanced-security-policies)
10. [Monitoring and Alerting](#10-monitoring-and-alerting)

---

## 1. Environment Setup

### 1.1 System Preparation

Start with a clean Ubuntu 20.04+ or CentOS 8+ system:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y curl wget git htop

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Logout and login to refresh group membership
exit
```

### 1.2 AutoSec Installation

```bash
# Clone the repository
git clone https://github.com/GizzZmo/AutoSec.git
cd AutoSec

# Set up directory structure
mkdir -p data/geoip logs backup
```

### 1.3 GeoIP Database Setup

```bash
# Register for MaxMind GeoLite2 (free account)
echo "Visit: https://www.maxmind.com/en/geolite2/signup"
echo "Download GeoLite2-City.mmdb"

# For this tutorial, we'll use a placeholder (replace with actual file)
touch data/geoip/GeoLite2-City.mmdb
echo "⚠️  Remember to replace with actual GeoLite2-City.mmdb file"
```

---

## 2. Initial Configuration

### 2.1 Environment Configuration

```bash
# Copy environment template
cp backend/.env.example backend/.env

# Generate secure secrets
JWT_SECRET=$(openssl rand -base64 64)
REFRESH_SECRET=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 16)

# Configure environment
cat > backend/.env << EOF
# Application Settings
NODE_ENV=production
PORT=8080
LOG_LEVEL=info
FRONTEND_URL=http://localhost:3000

# Security Settings
JWT_SECRET=$JWT_SECRET
JWT_REFRESH_SECRET=$REFRESH_SECRET
JWT_EXPIRES_IN=24h
BCRYPT_ROUNDS=12

# Database Settings
PG_HOST=autosec-postgres
PG_PORT=5432
PG_USER=autosec_user
PG_PASSWORD=$DB_PASSWORD
PG_DATABASE=autosec_db

MONGO_URI=mongodb://autosec-mongodb:27017/autosec_logs
REDIS_URL=redis://autosec-redis:6379
RABBITMQ_URL=amqp://guest:guest@autosec-rabbitmq:5672

# GeoIP Configuration
GEOIP_DB_PATH=/app/data/geoip/GeoLite2-City.mmdb

# External Integrations (we'll configure these later)
THREAT_INTEL_API_KEY=
FIREWALL_API_KEY=
EOF

echo "✅ Environment configured with secure secrets"
```

### 2.2 Deploy AutoSec

```bash
# Start all services
docker compose up --build -d

# Monitor startup (this may take 2-3 minutes)
echo "Waiting for services to start..."
sleep 30

# Check service health
docker compose ps
```

### 2.3 Initialize the System

```bash
# Wait for databases to be ready
echo "Waiting for databases..."
sleep 60

# Run database migrations
docker compose exec autosec-backend npm run db:migrate

# Seed initial data
docker compose exec autosec-backend npm run db:seed

# Create admin user
docker compose exec autosec-backend npm run create-admin
# Follow the prompts to create your admin account
```

### 2.4 Verify Installation

```bash
# Test API health
curl -s http://localhost:8080/api/health | jq .

# Test frontend
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
# Should return 200

echo "✅ AutoSec is running!"
echo "🌐 Frontend: http://localhost:3000"
echo "📡 API: http://localhost:8080/api"
echo "📚 API Docs: http://localhost:8080/api/docs"
```

---

## 3. User and Role Management

### 3.1 Access the Web Interface

Open your web browser and navigate to `http://localhost:3000`

1. **Login** with the admin credentials you created
2. **Explore the Dashboard** - familiarize yourself with the layout
3. **Check System Status** - ensure all components are green

### 3.2 Create Additional Users

Navigate to **Settings** → **User Management**:

```javascript
// Example users to create through the UI:
const users = [
  {
    email: "analyst@company.com",
    firstName: "Security",
    lastName: "Analyst",
    role: "analyst",
    password: "SecurePassword123!"
  },
  {
    email: "viewer@company.com",
    firstName: "SOC",
    lastName: "Viewer",
    role: "viewer",
    password: "ViewerPassword123!"
  }
];
```

**Via API (alternative method):**
```bash
# Get admin token first
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"your_admin_password"}' | jq -r .data.token)

# Create analyst user
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@company.com",
    "firstName": "Security",
    "lastName": "Analyst",
    "role": "analyst",
    "password": "SecurePassword123!"
  }'
```

### 3.3 Configure Role Permissions

Understanding AutoSec's role-based access control:

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Admin** | Full system access | System administrators |
| **Analyst** | Create/modify rules, analyze threats | Security analysts |
| **Viewer** | Read-only access | SOC operators, management |

Test different role permissions by logging in as different users.

---

## 4. Firewall Integration

### 4.1 Configure iptables Integration (Linux)

This is the easiest integration to test:

```bash
# Test iptables integration via API
curl -X POST http://localhost:8080/api/integrations/firewall/test \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "iptables",
    "config": {
      "sudo": true,
      "chain": "INPUT"
    },
    "testIP": "192.168.100.100"
  }'
```

### 4.2 Configure Palo Alto Integration

If you have a Palo Alto firewall:

```bash
# Configure Palo Alto integration
curl -X POST http://localhost:8080/api/integrations/firewall \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Main Firewall",
    "type": "paloalto",
    "config": {
      "hostname": "firewall.company.com",
      "username": "api_user",
      "password": "api_password",
      "vsys": "vsys1"
    },
    "enabled": true
  }'
```

### 4.3 Test Firewall Integration

```bash
# Create a test blocking rule
curl -X POST http://localhost:8080/api/rules \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ip",
    "value": "192.168.100.100",
    "action": "block",
    "reason": "Tutorial test - malicious IP",
    "severity": "high",
    "automate_firewall": true
  }'

# Verify the rule was created and applied
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/rules | jq '.data.rules[0]'
```

---

## 5. Threat Detection Setup

### 5.1 Configure Threat Intelligence Feeds

```bash
# Enable built-in threat detection
curl -X PUT http://localhost:8080/api/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "threat_detection": {
      "enabled": true,
      "sensitivity": "medium",
      "auto_block": true,
      "feeds": {
        "builtin": true,
        "external": []
      }
    }
  }'
```

### 5.2 Test Log Ingestion

```bash
# Send sample security logs
curl -X POST http://localhost:8080/api/logs \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "10.0.0.100",
    "destination_ip": "192.168.1.10",
    "source_port": 12345,
    "destination_port": 22,
    "protocol": "TCP",
    "action": "ALLOW",
    "bytes_sent": 1024,
    "bytes_received": 512,
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "metadata": {
      "user_agent": "SSH-2.0-OpenSSH_8.0",
      "session_id": "session_123"
    }
  }'

# Send suspicious activity log
curl -X POST http://localhost:8080/api/logs \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.100.100",
    "destination_ip": "192.168.1.10",
    "source_port": 54321,
    "destination_port": 22,
    "protocol": "TCP",
    "action": "DENY",
    "bytes_sent": 0,
    "bytes_received": 0,
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "metadata": {
      "reason": "Multiple failed login attempts",
      "attempts": 15
    }
  }'
```

### 5.3 Verify Threat Detection

```bash
# Check for generated threats
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/api/logs?action=DENY&limit=10" | jq .

# Check dashboard for threat updates
echo "Visit http://localhost:3000/dashboard to see threat activity"
```

---

## 6. Behavioral Analysis Configuration

### 6.1 Enable Behavioral Analysis

```bash
# Configure behavioral analysis
curl -X PUT http://localhost:8080/api/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "behavioral_analysis": {
      "enabled": true,
      "user_behavior": {
        "enabled": true,
        "learning_period_days": 7,
        "anomaly_threshold": 0.8
      },
      "network_behavior": {
        "enabled": true,
        "baseline_period_hours": 24,
        "detection_sensitivity": "medium"
      }
    }
  }'
```

### 6.2 Generate Test Behavioral Data

```bash
# Simulate normal user behavior
for i in {1..10}; do
  curl -X POST http://localhost:8080/api/logs \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "source_ip": "192.168.1.50",
      "destination_ip": "192.168.1.10",
      "source_port": '$((3000 + i))',
      "destination_port": 80,
      "protocol": "TCP",
      "action": "ALLOW",
      "bytes_sent": '$((1024 * i))',
      "bytes_received": '$((2048 * i))',
      "timestamp": "'$(date -u -d "$i minutes ago" +%Y-%m-%dT%H:%M:%S.%3NZ)'",
      "metadata": {
        "user_id": "user123",
        "session_id": "normal_session_'$i'"
      }
    }'
  sleep 1
done

# Simulate anomalous behavior
curl -X POST http://localhost:8080/api/logs \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.50",
    "destination_ip": "10.0.0.100",
    "source_port": 65432,
    "destination_port": 443,
    "protocol": "TCP",
    "action": "ALLOW",
    "bytes_sent": 1048576,
    "bytes_received": 10485760,
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "metadata": {
      "user_id": "user123",
      "session_id": "anomalous_session",
      "unusual_time": true,
      "large_transfer": true
    }
  }'
```

### 6.3 Trigger Behavior Analysis

```bash
# Manually trigger analysis
curl -X POST http://localhost:8080/api/behavior/analyze \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "time_range": {
      "start": "'$(date -u -d "1 hour ago" +%Y-%m-%dT%H:%M:%S.%3NZ)'",
      "end": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"
    },
    "analysis_type": "full"
  }'

# Check analysis results
sleep 10
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/api/behavior/user/user123" | jq .
```

---

## 7. Dashboard Customization

### 7.1 Explore the Dashboard

Navigate to `http://localhost:3000/dashboard` and explore:

1. **Threat Overview** - Real-time threat statistics
2. **Network Activity** - Traffic patterns and anomalies
3. **Geographic View** - Global threat distribution
4. **Recent Events** - Latest security events
5. **System Health** - Component status

### 7.2 Customize Dashboard Widgets

Through the web interface:
1. Click **Dashboard Settings** (gear icon)
2. **Add/Remove Widgets** according to your needs
3. **Drag and Drop** to rearrange layout
4. **Configure Refresh Intervals** for real-time updates

### 7.3 Create Custom Views

```bash
# Create custom dashboard view via API
curl -X POST http://localhost:8080/api/dashboards \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SOC Overview",
    "widgets": [
      {
        "type": "threat_summary",
        "position": {"x": 0, "y": 0, "w": 6, "h": 4},
        "config": {"time_range": "24h"}
      },
      {
        "type": "geographic_threats",
        "position": {"x": 6, "y": 0, "w": 6, "h": 4},
        "config": {"show_blocked": true}
      },
      {
        "type": "recent_events",
        "position": {"x": 0, "y": 4, "w": 12, "h": 6},
        "config": {"limit": 50, "severity": "high"}
      }
    ],
    "is_default": false
  }'
```

---

## 8. API Integration

### 8.1 API Authentication

```bash
# Store your admin token for API calls
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"your_admin_password"}' | jq -r .data.token)

echo "Admin Token: $ADMIN_TOKEN"
```

### 8.2 Common API Operations

```bash
# Get system health
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/health | jq .

# List all rules
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/rules | jq .

# Search logs
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/api/logs/search?q=DENY&limit=5" | jq .

# Get user behavior analysis
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/behavior/user/user123 | jq .

# Get network statistics
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/analytics/network/traffic | jq .
```

### 8.3 Bulk Operations

```bash
# Bulk log ingestion
curl -X POST http://localhost:8080/api/logs/batch \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {
        "source_ip": "10.0.0.1",
        "destination_ip": "192.168.1.100",
        "protocol": "HTTP",
        "action": "ALLOW",
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"
      },
      {
        "source_ip": "10.0.0.2",
        "destination_ip": "192.168.1.101",
        "protocol": "HTTPS",
        "action": "ALLOW",
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"
      }
    ]
  }'

# Bulk rule creation
curl -X POST http://localhost:8080/api/rules/batch \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [
      {
        "type": "ip",
        "value": "192.168.200.1",
        "action": "block",
        "reason": "Known malicious IP",
        "severity": "high"
      },
      {
        "type": "ip_range",
        "value": "10.10.10.0/24",
        "action": "monitor",
        "reason": "Suspicious subnet",
        "severity": "medium"
      }
    ]
  }'
```

---

## 9. Advanced Security Policies

### 9.1 Geo-blocking Configuration

```bash
# Block traffic from specific countries
curl -X POST http://localhost:8080/api/rules \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "country",
    "value": "CN",
    "action": "block",
    "reason": "Geographic restriction policy",
    "severity": "medium",
    "automate_firewall": true
  }'

# Monitor traffic from specific regions
curl -X POST http://localhost:8080/api/rules \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "country",
    "value": "RU",
    "action": "monitor",
    "reason": "Enhanced monitoring for this region",
    "severity": "low"
  }'
```

### 9.2 Behavioral Rules

```bash
# Create behavioral anomaly rules
curl -X POST http://localhost:8080/api/rules \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "behavior",
    "value": "anomalous_login_pattern",
    "action": "alert",
    "reason": "Unusual login behavior detected",
    "severity": "high",
    "conditions": {
      "risk_score_threshold": 0.8,
      "anomaly_types": ["unusual_time", "unusual_location", "unusual_device"]
    }
  }'
```

### 9.3 Time-based Rules

```bash
# Create temporary blocking rule
EXPIRE_TIME=$(date -u -d "+24 hours" +%Y-%m-%dT%H:%M:%S.%3NZ)

curl -X POST http://localhost:8080/api/rules \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ip",
    "value": "192.168.200.200",
    "action": "block",
    "reason": "Temporary block for investigation",
    "severity": "medium",
    "expires_at": "'$EXPIRE_TIME'"
  }'
```

---

## 10. Monitoring and Alerting

### 10.1 Configure Alerting

```bash
# Configure email alerts
curl -X PUT http://localhost:8080/api/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alerting": {
      "enabled": true,
      "email": {
        "enabled": true,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_user": "alerts@company.com",
        "smtp_password": "app_password",
        "from_address": "autosec@company.com",
        "to_addresses": ["soc@company.com", "admin@company.com"]
      },
      "thresholds": {
        "high_severity_immediate": true,
        "medium_severity_threshold": 5,
        "low_severity_threshold": 20
      }
    }
  }'

# Configure webhook alerts
curl -X PUT http://localhost:8080/api/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alerting": {
      "webhook": {
        "enabled": true,
        "url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
        "format": "slack",
        "retry_attempts": 3
      }
    }
  }'
```

### 10.2 Monitor System Health

```bash
# Set up system monitoring script
cat > monitor_autosec.sh << 'EOF'
#!/bin/bash

ADMIN_TOKEN="YOUR_ADMIN_TOKEN_HERE"
API_URL="http://localhost:8080/api"

# Check system health
HEALTH=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" $API_URL/health)
STATUS=$(echo $HEALTH | jq -r .status)

if [ "$STATUS" != "healthy" ]; then
    echo "❌ AutoSec health check failed: $HEALTH"
    # Send alert (add your alerting logic here)
else
    echo "✅ AutoSec is healthy"
fi

# Check threat levels
THREATS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$API_URL/analytics/threats?period=1h")
HIGH_THREATS=$(echo $THREATS | jq '.data.high_severity // 0')

if [ "$HIGH_THREATS" -gt 10 ]; then
    echo "🚨 High threat activity detected: $HIGH_THREATS high-severity threats in the last hour"
fi

# Check service resource usage
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep autosec
EOF

chmod +x monitor_autosec.sh

# Run monitoring check
./monitor_autosec.sh
```

### 10.3 Performance Monitoring

```bash
# Get system metrics
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/metrics | jq .

# Get processing statistics
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/analytics/processing-stats | jq .

# Monitor database performance
docker compose exec autosec-postgres psql -U autosec_user -d autosec_db -c "
SELECT 
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes
FROM pg_stat_user_tables 
ORDER BY n_tup_ins DESC;
"
```

---

## 🎉 Tutorial Completion

Congratulations! You have successfully:

✅ **Deployed AutoSec** with all components  
✅ **Configured security integrations** (firewalls, threat detection)  
✅ **Set up behavioral analysis** with ML-powered anomaly detection  
✅ **Created security rules and policies** for automated threat response  
✅ **Customized dashboards** for your security operations center  
✅ **Integrated with APIs** for automated security workflows  
✅ **Configured monitoring and alerting** for proactive threat management  

## 🚀 Next Steps

### Immediate Actions:
1. **Replace GeoIP database** with actual MaxMind GeoLite2-City.mmdb
2. **Configure SSL/TLS** for production deployment
3. **Set up proper backup procedures** for your data
4. **Train your team** on using AutoSec effectively

### Advanced Configuration:
1. **Integrate with your SIEM** for centralized logging
2. **Configure SSO** with your identity provider
3. **Set up high availability** deployment
4. **Implement custom ML models** for your specific threat landscape

### Production Deployment:
1. **Security hardening** - follow security best practices
2. **Performance tuning** - optimize for your traffic volume
3. **Compliance configuration** - meet your regulatory requirements
4. **Disaster recovery** - implement backup and recovery procedures

## 📚 Additional Resources

- **[API Documentation](../api/endpoints.md)** - Complete API reference
- **[Security Guide](../security/architecture.md)** - Security best practices
- **[Deployment Guide](../deployment/installation.md)** - Production deployment
- **[Troubleshooting](../user-guide/troubleshooting.md)** - Common issues and solutions

## 🆘 Getting Help

- **GitHub Issues**: Report bugs and request features
- **Community Forum**: Get help from other users
- **Documentation**: Comprehensive guides and references
- **Professional Support**: Enterprise support available

---

**🎯 You're now ready to protect your network with AutoSec's advanced AI-powered cybersecurity platform!**