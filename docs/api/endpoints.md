# AutoSec API Reference

This document provides comprehensive documentation for all AutoSec API endpoints.

## 🔐 Authentication

All API requests require authentication using JWT tokens.

### Get Access Token
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "123",
      "email": "user@example.com",
      "role": "admin"
    }
  }
}
```

### Use Token in Requests
Include the token in the Authorization header:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 📊 Core Endpoints

### Health Check
Check system health and status.

```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-01T12:00:00Z",
  "services": {
    "database": "connected",
    "redis": "connected",
    "rabbitmq": "connected"
  }
}
```

### System Status
Get detailed system information.

```http
GET /api/status
```

**Response:**
```json
{
  "version": "1.0.0",
  "uptime": 86400,
  "memory": {
    "used": 512000000,
    "total": 1073741824
  },
  "database": {
    "postgres": "connected",
    "mongodb": "connected"
  }
}
```

## 👥 User Management

### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "securepassword",
  "firstName": "John",
  "lastName": "Doe"
}
```

### Get User Profile
```http
GET /api/auth/profile
Authorization: Bearer {token}
```

### Update User Profile
```http
PUT /api/auth/profile
Authorization: Bearer {token}
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Smith",
  "email": "john.smith@example.com"
}
```

### List Users (Admin Only)
```http
GET /api/users?page=1&limit=10&role=admin
Authorization: Bearer {token}
```

## 🛡️ Security Rules Management

### Get Blocking Rules
Retrieve all blocking rules with pagination and filtering.

```http
GET /api/rules?page=1&limit=10&type=ip&status=active
Authorization: Bearer {token}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "rules": [
      {
        "id": "rule123",
        "type": "ip",
        "value": "192.168.1.100",
        "action": "block",
        "reason": "Suspicious activity",
        "severity": "high",
        "created_at": "2025-01-01T12:00:00Z",
        "expires_at": null,
        "is_active": true
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 150,
      "pages": 15
    }
  }
}
```

### Create Blocking Rule
```http
POST /api/rules
Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "ip",
  "value": "192.168.1.100",
  "action": "block",
  "reason": "Malicious activity detected",
  "severity": "high",
  "expires_at": "2025-01-31T23:59:59Z"
}
```

**Rule Types:**
- `ip` - Single IP address
- `ip_range` - IP range (CIDR notation)
- `country` - Country code (ISO 3166-1 alpha-2)
- `organization` - Organization/ASN
- `domain` - Domain name

### Update Blocking Rule
```http
PUT /api/rules/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "reason": "Updated threat assessment",
  "severity": "medium",
  "expires_at": "2025-02-28T23:59:59Z"
}
```

### Delete Blocking Rule
```http
DELETE /api/rules/{id}
Authorization: Bearer {token}
```

## 📝 Log Management

### Ingest Logs
Submit log entries for processing and analysis.

```http
POST /api/logs
Authorization: Bearer {token}
Content-Type: application/json

{
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "source_port": 12345,
  "destination_port": 80,
  "protocol": "TCP",
  "action": "ALLOW",
  "bytes_sent": 1024,
  "bytes_received": 2048,
  "timestamp": "2025-01-01T12:00:00Z",
  "metadata": {
    "user_agent": "Mozilla/5.0...",
    "session_id": "sess123"
  }
}
```

### Batch Log Ingestion
```http
POST /api/logs/batch
Authorization: Bearer {token}
Content-Type: application/json

{
  "logs": [
    {
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.1",
      "protocol": "TCP",
      "action": "ALLOW",
      "timestamp": "2025-01-01T12:00:00Z"
    },
    {
      "source_ip": "192.168.1.101",
      "destination_ip": "10.0.0.2",
      "protocol": "UDP",
      "action": "DENY",
      "timestamp": "2025-01-01T12:01:00Z"
    }
  ]
}
```

### Retrieve Logs
```http
GET /api/logs?page=1&limit=100&start_time=2025-01-01T00:00:00Z&end_time=2025-01-01T23:59:59Z&source_ip=192.168.1.100
Authorization: Bearer {token}
```

**Query Parameters:**
- `page` - Page number (default: 1)
- `limit` - Results per page (max: 1000, default: 100)
- `start_time` - Filter logs after this time (ISO 8601)
- `end_time` - Filter logs before this time (ISO 8601)
- `source_ip` - Filter by source IP
- `destination_ip` - Filter by destination IP
- `protocol` - Filter by protocol (TCP, UDP, ICMP)
- `action` - Filter by action (ALLOW, DENY, BLOCK)

### Search Logs
Full-text search across log entries.

```http
GET /api/logs/search?q=malware&fields=metadata,reason&page=1&limit=50
Authorization: Bearer {token}
```

## 🧠 Behavioral Analysis

### Get User Behavior Analysis
```http
GET /api/behavior/user/{userId}
Authorization: Bearer {token}
```

**Response:**
```json
{
  "user_id": "user123",
  "risk_score": 0.75,
  "anomalies": [
    {
      "type": "unusual_login_time",
      "severity": "medium",
      "description": "Login at unusual hour",
      "timestamp": "2025-01-01T03:00:00Z"
    }
  ],
  "patterns": {
    "typical_login_hours": [8, 9, 10, 17, 18],
    "common_locations": ["Office", "Home"],
    "device_fingerprints": ["desktop-123", "mobile-456"]
  }
}
```

### Get Network Behavior Analysis
```http
GET /api/behavior/network?start_time=2025-01-01T00:00:00Z&end_time=2025-01-01T23:59:59Z
Authorization: Bearer {token}
```

### Trigger Behavior Analysis
```http
POST /api/behavior/analyze
Authorization: Bearer {token}
Content-Type: application/json

{
  "user_id": "user123",
  "time_range": {
    "start": "2025-01-01T00:00:00Z",
    "end": "2025-01-01T23:59:59Z"
  },
  "analysis_type": "full"
}
```

### Get Risk Scores
```http
GET /api/behavior/risk-scores?threshold=0.7&limit=50
Authorization: Bearer {token}
```

## 🌍 GeoIP Services

### Single IP Lookup
```http
GET /api/geoip?ip=8.8.8.8
Authorization: Bearer {token}
```

**Response:**
```json
{
  "ip": "8.8.8.8",
  "country": "US",
  "country_name": "United States",
  "region": "CA",
  "region_name": "California",
  "city": "Mountain View",
  "latitude": 37.4056,
  "longitude": -122.0775,
  "timezone": "America/Los_Angeles",
  "isp": "Google LLC",
  "organization": "Google Public DNS"
}
```

### Bulk IP Lookup
```http
POST /api/geoip/bulk
Authorization: Bearer {token}
Content-Type: application/json

{
  "ips": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
}
```

## 🔐 Multi-Factor Authentication

### Setup MFA
```http
POST /api/mfa/setup
Authorization: Bearer {token}
```

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSU...",
  "backup_codes": [
    "12345678",
    "87654321"
  ]
}
```

### Verify MFA Token
```http
POST /api/mfa/verify
Authorization: Bearer {token}
Content-Type: application/json

{
  "token": "123456"
}
```

### Disable MFA
```http
POST /api/mfa/disable
Authorization: Bearer {token}
Content-Type: application/json

{
  "password": "current_password"
}
```

## 📊 Analytics and Reporting

### Dashboard Data
```http
GET /api/analytics/dashboard
Authorization: Bearer {token}
```

### Threat Statistics
```http
GET /api/analytics/threats?period=24h&group_by=severity
Authorization: Bearer {token}
```

### Network Traffic Analysis
```http
GET /api/analytics/network/traffic?start_time=2025-01-01T00:00:00Z&end_time=2025-01-01T23:59:59Z
Authorization: Bearer {token}
```

### Export Data
```http
GET /api/analytics/export?format=csv&data_type=logs&start_time=2025-01-01T00:00:00Z
Authorization: Bearer {token}
```

## ⚙️ System Configuration

### Get System Settings
```http
GET /api/settings
Authorization: Bearer {token}
```

### Update System Settings
```http
PUT /api/settings
Authorization: Bearer {token}
Content-Type: application/json

{
  "threat_detection": {
    "enabled": true,
    "sensitivity": "high"
  },
  "notifications": {
    "email_alerts": true,
    "webhook_url": "https://example.com/webhook"
  }
}
```

## 🚫 Error Responses

All errors follow a consistent format:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_INPUT",
    "message": "The provided input is invalid",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    }
  }
}
```

### Common Error Codes
- `UNAUTHORIZED` (401) - Invalid or missing authentication token
- `FORBIDDEN` (403) - Insufficient permissions
- `NOT_FOUND` (404) - Resource not found
- `INVALID_INPUT` (400) - Invalid request data
- `RATE_LIMITED` (429) - Too many requests
- `INTERNAL_ERROR` (500) - Server error

## 📈 Rate Limiting

API endpoints are rate-limited to prevent abuse:

- **Authentication endpoints**: 5 requests per minute per IP
- **Data retrieval endpoints**: 100 requests per minute per user
- **Data modification endpoints**: 30 requests per minute per user
- **Bulk operations**: 10 requests per minute per user

Rate limit headers are included in all responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## 🔧 SDK and Libraries

Official SDKs are available for popular programming languages:

- **JavaScript/Node.js**: `npm install autosec-sdk`
- **Python**: `pip install autosec-sdk`
- **Go**: `go get github.com/autosec/go-sdk`
- **Java**: Maven/Gradle artifacts available

### JavaScript Example
```javascript
const AutoSec = require('autosec-sdk');

const client = new AutoSec({
  apiUrl: 'http://localhost:8080/api',
  token: 'your-jwt-token'
});

// Create a blocking rule
const rule = await client.rules.create({
  type: 'ip',
  value: '192.168.1.100',
  action: 'block',
  reason: 'Suspicious activity'
});
```

---

For more examples and detailed integration guides, see the [Architecture Overview](../developer-guide/architecture.md) and [Main README](../../README.md).