# Getting Started with AutoSec

Welcome to AutoSec! This guide will help you get AutoSec up and running in your environment.

## 📋 Prerequisites

Before installing AutoSec, ensure your system meets the following requirements:

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+) or macOS 10.15+
- **CPU**: 4+ cores recommended (2+ minimum)
- **RAM**: 8GB+ recommended (4GB minimum)
- **Storage**: 20GB+ available space
- **Network**: Internet connection for threat intelligence feeds

### Software Requirements
- **Docker**: 20.10+ (Latest version recommended)
- **Docker Compose**: 2.0+ 
- **Git**: Latest version
- **Node.js**: 18+ (for development only)
- **curl**: For testing API endpoints

### GeoIP Database
AutoSec requires the MaxMind GeoLite2 database for geographic IP analysis:
1. Register for a free account at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. Download the GeoLite2-City.mmdb binary database
3. Place it in the `data/geoip/` directory

## 🚀 Quick Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/GizzZmo/AutoSec.git
cd AutoSec
```

### Step 2: Setup GeoIP Database
```bash
# Create the directory
mkdir -p data/geoip

# Download from MaxMind and place the file
# (Replace YOUR_DOWNLOAD_URL with your actual MaxMind download URL)
wget -O data/geoip/GeoLite2-City.mmdb "YOUR_MAXMIND_DOWNLOAD_URL"
```

### Step 3: Configure Environment
```bash
# Copy environment template
cp backend/.env.example backend/.env

# Generate secure secrets
openssl rand -base64 64  # Use for JWT_SECRET
openssl rand -base64 32  # Use for encryption keys

# Edit backend/.env with your configuration
nano backend/.env
```

**Important**: Change the default passwords and set secure JWT secrets in the `.env` file.

### Step 4: Deploy AutoSec
```bash
# Build and start all services
docker compose up --build -d

# Check service health (may take 2-3 minutes)
docker compose ps
```

### Step 5: Initialize the System
```bash
# Wait for services to be healthy, then initialize
docker compose exec autosec-backend npm run db:migrate
docker compose exec autosec-backend npm run db:seed

# Optional: Create admin user
docker compose exec autosec-backend npm run create-admin
```

## 🌐 Access Points

Once deployed, you can access AutoSec through the following endpoints:

- **Web Console**: http://localhost:3000
- **API Gateway**: http://localhost:8080/api
- **API Documentation**: http://localhost:8080/api/docs (Swagger UI)
- **RabbitMQ Management**: http://localhost:15672 (guest/guest)

## ✅ Verification

Test your installation with these commands:

```bash
# Test API health
curl http://localhost:8080/api/health

# Test GeoIP functionality
curl "http://localhost:8080/api/geoip?ip=8.8.8.8"

# Check service logs
docker compose logs -f autosec-backend
docker compose logs -f autosec-frontend
```

Expected responses:
- Health check should return `{"status": "healthy"}`
- GeoIP should return location information for the IP
- Logs should show successful startup messages

## 🎯 First Steps

### 1. Access the Web Console
Navigate to http://localhost:3000 in your browser.

### 2. Create Your Account
- Click "Register" if you haven't created an admin user
- Or log in with the admin credentials you created

### 3. Explore the Dashboard
- Review system status and metrics
- Check the threat feed for real-time updates
- Examine the behavioral analysis overview

### 4. Configure Your First Rule
- Navigate to the "Blocklist" section
- Create a test blocking rule
- Test the rule with a sample IP address

### 5. Test Log Ingestion
Try sending a test log entry:
```bash
curl -X POST http://localhost:8080/api/logs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "port": 80,
    "protocol": "TCP",
    "action": "ALLOW",
    "timestamp": "2025-01-01T12:00:00Z"
  }'
```

## 🔧 Basic Configuration

### Environment Variables
Key settings in `backend/.env`:

```bash
# Security Settings
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=24h

# Database Settings
PG_PASSWORD=change-this-password
MONGO_URI=mongodb://autosec-mongodb:27017/autosec_logs

# External Services
FRONTEND_URL=http://localhost:3000
```

### Firewall Integration
To connect AutoSec to your firewall:

1. Navigate to "Settings" → "Integrations"
2. Select your firewall type (Palo Alto, Cisco ASA, or iptables)
3. Configure connection details
4. Test the connection
5. Enable automatic blocking

### User Management
- **Admin Users**: Can manage all aspects of the system
- **Analyst Users**: Can view data and create rules
- **Viewer Users**: Read-only access to dashboards

## 🚨 Troubleshooting

### Common Issues

**Services won't start:**
```bash
# Check Docker status
docker compose ps

# View service logs
docker compose logs autosec-backend
docker compose logs autosec-frontend
```

**GeoIP not working:**
- Ensure GeoLite2-City.mmdb is in `data/geoip/`
- Check file permissions: `chmod 644 data/geoip/GeoLite2-City.mmdb`

**Can't connect to web interface:**
- Verify frontend container is running
- Check port 3000 is not blocked by firewall
- Review frontend logs for errors

**Database connection errors:**
- Ensure database containers are healthy
- Check environment variables in `.env`
- Verify network connectivity between containers

### Getting Help

- **Documentation**: Check the [full documentation](../README.md)
- **Issues**: Report bugs on [GitHub Issues](https://github.com/GizzZmo/AutoSec/issues)
- **Community**: Join discussions on [GitHub Discussions](https://github.com/GizzZmo/AutoSec/discussions)

## 📚 Next Steps

Now that AutoSec is running:

1. **Read the User Guide**: Learn about all features and capabilities
2. **Configure Integrations**: Connect your existing security tools
3. **Set Up Monitoring**: Configure alerts and notifications
4. **Train Your Team**: Share access and train users on the platform
5. **Customize Dashboards**: Tailor the interface to your needs

## 🔒 Security Notes

- **Change Default Passwords**: Never use default passwords in production
- **Use HTTPS**: Configure SSL/TLS certificates for production deployment
- **Regular Updates**: Keep AutoSec and dependencies updated
- **Backup Data**: Implement regular backup procedures
- **Monitor Logs**: Review system logs regularly for security events

---

Welcome to AutoSec! You're now ready to start securing your network with advanced AI-powered threat detection.