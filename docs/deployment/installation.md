# AutoSec Installation Guide

This comprehensive guide covers installation options for AutoSec, from local development to production deployment.

## 📋 Prerequisites

### System Requirements

**Minimum Requirements:**
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 20 GB available space
- **Network**: Internet connection for threat intelligence feeds

**Recommended Requirements:**
- **CPU**: 4+ cores, 2.5 GHz+
- **RAM**: 8 GB+
- **Storage**: 50 GB+ SSD storage
- **Network**: High-bandwidth connection for large-scale deployments

### Software Prerequisites

**Required Software:**
- **Docker**: 20.10+ (Latest version recommended)
- **Docker Compose**: 2.0+
- **Git**: Latest version
- **curl**: For API testing and health checks

**Optional (for development):**
- **Node.js**: 18+ for local development (20+ recommended)
- **npm/yarn**: Package manager
- **PostgreSQL Client**: For database management
- **MongoDB Compass**: For MongoDB management

### Network Requirements

**Ports Used by AutoSec:**
- **3000**: Frontend web interface
- **8080**: Backend API server
- **5432**: PostgreSQL database (internal)
- **27017**: MongoDB database (internal)
- **6379**: Redis cache (internal)
- **5672**: RabbitMQ AMQP (internal)
- **15672**: RabbitMQ Management UI (optional)

**Firewall Configuration:**
```bash
# Allow inbound traffic on required ports
sudo ufw allow 3000/tcp
sudo ufw allow 8080/tcp

# Optional: RabbitMQ management (development only)
sudo ufw allow 15672/tcp
```

## 🚀 Quick Installation (Docker Compose)

### Step 1: Clone Repository
```bash
git clone https://github.com/GizzZmo/AutoSec.git
cd AutoSec
```

### Step 2: Setup GeoIP Database
AutoSec requires the MaxMind GeoLite2 database for IP geolocation:

```bash
# Create GeoIP directory
mkdir -p data/geoip

# Register at MaxMind (free): https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb and place it in data/geoip/

# Verify the file
ls -la data/geoip/GeoLite2-City.mmdb
```

### Step 3: Configure Environment
```bash
# Copy environment template
cp backend/.env.example backend/.env

# Generate secure secrets
echo "JWT_SECRET=$(openssl rand -base64 64)" >> backend/.env
echo "ENCRYPTION_KEY=$(openssl rand -base64 32)" >> backend/.env

# Edit configuration (important!)
nano backend/.env
```

**Critical Settings to Change:**
```bash
# Security (REQUIRED)
JWT_SECRET=your-super-secure-jwt-secret-here
JWT_REFRESH_SECRET=your-refresh-token-secret-here

# Database Passwords (REQUIRED)
PG_PASSWORD=your-secure-postgres-password
MONGO_INITDB_ROOT_PASSWORD=your-secure-mongo-password

# Application Settings
NODE_ENV=production
FRONTEND_URL=http://your-domain.com:3000

# GeoIP Database
GEOIP_DB_PATH=/app/data/geoip/GeoLite2-City.mmdb
```

### Step 4: Deploy AutoSec
```bash
# Build and start all services
docker compose up --build -d

# Monitor startup (may take 2-3 minutes)
docker compose logs -f

# Check service health
docker compose ps
```

### Step 5: Initialize System
```bash
# Wait for all services to be healthy
docker compose exec autosec-backend npm run db:migrate
docker compose exec autosec-backend npm run db:seed

# Create initial admin user
docker compose exec autosec-backend npm run create-admin
# Follow prompts to create admin account
```

### Step 6: Verify Installation
```bash
# Test API health
curl http://localhost:8080/api/health

# Test frontend
curl http://localhost:3000

# Test GeoIP functionality
curl "http://localhost:8080/api/geoip?ip=8.8.8.8"
```

**Expected Responses:**
- Health check: `{"status":"healthy",...}`
- Frontend: HTML response with React app
- GeoIP: Location data for the IP address

## 🔧 Advanced Installation Options

### Production Docker Deployment

For production environments, use the production Docker Compose configuration:

```bash
# Use production compose file
cp docker-compose.prod.yml docker-compose.override.yml

# Configure production settings
cp backend/.env.production backend/.env

# Deploy with production settings
docker compose -f docker-compose.yml -f docker-compose.override.yml up -d
```

**Production Compose Example:**
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  autosec-backend:
    environment:
      NODE_ENV: production
      LOG_LEVEL: info
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  autosec-frontend:
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '0.5'
          memory: 512M

  # External load balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    depends_on:
      - autosec-frontend
      - autosec-backend
```

### Kubernetes Deployment

#### Prerequisites
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

#### Deploy with Helm
```bash
# Add AutoSec Helm repository
helm repo add autosec https://charts.autosec.io
helm repo update

# Install AutoSec
helm install autosec autosec/autosec-platform \
  --set global.domain=your-domain.com \
  --set postgresql.auth.password=your-secure-password \
  --set mongodb.auth.rootPassword=your-secure-password \
  --set backend.auth.jwtSecret=your-jwt-secret

# Check deployment status
kubectl get pods -l app.kubernetes.io/instance=autosec
```

#### Manual Kubernetes Deployment
```bash
# Create namespace
kubectl create namespace autosec

# Create secrets
kubectl create secret generic autosec-secrets \
  --from-literal=jwt-secret=$(openssl rand -base64 64) \
  --from-literal=postgres-password=$(openssl rand -base64 32) \
  --from-literal=mongo-password=$(openssl rand -base64 32) \
  -n autosec

# Deploy PostgreSQL
kubectl apply -f k8s/postgres.yaml -n autosec

# Deploy MongoDB
kubectl apply -f k8s/mongodb.yaml -n autosec

# Deploy Redis
kubectl apply -f k8s/redis.yaml -n autosec

# Deploy RabbitMQ
kubectl apply -f k8s/rabbitmq.yaml -n autosec

# Deploy AutoSec Backend
kubectl apply -f k8s/backend.yaml -n autosec

# Deploy AutoSec Frontend
kubectl apply -f k8s/frontend.yaml -n autosec

# Configure Ingress
kubectl apply -f k8s/ingress.yaml -n autosec
```

### Manual Installation (Without Docker)

#### Install Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20 (LTS)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-6.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/mongodb-archive-keyring.gpg] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-org

# Install Redis
sudo apt install -y redis-server

# Install RabbitMQ
sudo apt install -y rabbitmq-server
```

#### Configure Databases
```bash
# Configure PostgreSQL
sudo -u postgres createuser autosec_user
sudo -u postgres createdb autosec_db
sudo -u postgres psql -c "ALTER USER autosec_user PASSWORD 'your_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE autosec_db TO autosec_user;"

# Configure MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Configure Redis
sudo systemctl start redis
sudo systemctl enable redis

# Configure RabbitMQ
sudo systemctl start rabbitmq-server
sudo systemctl enable rabbitmq-server
sudo rabbitmq-plugins enable rabbitmq_management
```

#### Install AutoSec
```bash
# Clone repository
git clone https://github.com/GizzZmo/AutoSec.git
cd AutoSec

# Install backend dependencies
cd backend
npm install
cp .env.example .env
# Edit .env with your database configurations

# Run database migrations
npm run db:migrate
npm run db:seed

# Install frontend dependencies
cd ../frontend
npm install
npm run build

# Start services
cd ../backend
npm start &

# Serve frontend (using serve)
npm install -g serve
cd ../frontend
serve -s build -l 3000 &
```

## 🔒 SSL/TLS Configuration

### Let's Encrypt with Nginx

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

**Nginx Configuration:**
```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Frontend
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API
    location /api/ {
        proxy_pass http://localhost:8080/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

## 📊 Monitoring and Maintenance

### Health Monitoring

```bash
# Create health check script
cat > health_check.sh << 'EOF'
#!/bin/bash

API_URL="http://localhost:8080/api/health"
FRONTEND_URL="http://localhost:3000"

# Check API health
API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $API_URL)
if [ "$API_STATUS" != "200" ]; then
    echo "API health check failed: $API_STATUS"
    exit 1
fi

# Check frontend
FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $FRONTEND_URL)
if [ "$FRONTEND_STATUS" != "200" ]; then
    echo "Frontend health check failed: $FRONTEND_STATUS"
    exit 1
fi

echo "All services healthy"
EOF

chmod +x health_check.sh

# Add to cron for monitoring
crontab -e
# Add: */5 * * * * /path/to/health_check.sh || systemctl restart docker-compose@autosec
```

### Log Management

```bash
# Configure log rotation
sudo tee /etc/logrotate.d/autosec << EOF
/var/log/autosec/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

# Configure Docker log limits
# Add to docker-compose.yml:
services:
  autosec-backend:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"
```

### Backup Strategy

```bash
# Database backup script
cat > backup.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/backup/autosec"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup PostgreSQL
docker compose exec -T autosec-postgres pg_dump -U autosec_user autosec_db > $BACKUP_DIR/postgres_$DATE.sql

# Backup MongoDB
docker compose exec -T autosec-mongodb mongodump --archive > $BACKUP_DIR/mongodb_$DATE.archive

# Backup configuration
cp -r backend/.env data/ $BACKUP_DIR/config_$DATE/

# Compress backups older than 7 days
find $BACKUP_DIR -name "*.sql" -mtime +7 -exec gzip {} \;
find $BACKUP_DIR -name "*.archive" -mtime +7 -exec gzip {} \;

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
EOF

chmod +x backup.sh

# Schedule daily backups
crontab -e
# Add: 0 2 * * * /path/to/backup.sh
```

## 🚨 Troubleshooting

### Common Issues

**Services not starting:**
```bash
# Check Docker status
docker compose ps

# View logs
docker compose logs autosec-backend
docker compose logs autosec-frontend

# Restart specific service
docker compose restart autosec-backend
```

**Database connection errors:**
```bash
# Check database containers
docker compose exec autosec-postgres pg_isready -U autosec_user
docker compose exec autosec-mongodb mongosh --eval "db.adminCommand('ping')"

# Reset database (development only)
docker compose down -v
docker compose up -d
```

**Permission issues:**
```bash
# Fix file permissions
sudo chown -R $USER:$USER .
chmod -R 755 .

# Fix data directory permissions
sudo chown -R 999:999 data/
```

**Memory issues:**
```bash
# Check memory usage
docker stats

# Increase Docker memory limits
# Edit /etc/docker/daemon.json:
{
  "default-runtime": "runc",
  "default-shm-size": "128M",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  }
}

sudo systemctl restart docker
```

### Recovery Procedures

**Service Recovery:**
```bash
# Stop all services
docker compose down

# Remove containers and volumes (data loss!)
docker compose down -v

# Rebuild and restart
docker compose up --build -d

# Restore from backup
./restore.sh latest
```

**Database Recovery:**
```bash
# Restore PostgreSQL
docker compose exec -T autosec-postgres psql -U autosec_user -d autosec_db < backup/postgres_latest.sql

# Restore MongoDB
docker compose exec -T autosec-mongodb mongorestore --archive < backup/mongodb_latest.archive
```

## 🔧 Configuration Reference

### Environment Variables

**Security Settings:**
```bash
JWT_SECRET=                 # JWT signing secret (required)
JWT_EXPIRES_IN=24h         # Token expiration time
JWT_REFRESH_SECRET=        # Refresh token secret (required)
BCRYPT_ROUNDS=12           # Password hashing rounds
```

**Database Settings:**
```bash
PG_HOST=autosec-postgres   # PostgreSQL host
PG_PORT=5432               # PostgreSQL port
PG_USER=autosec_user       # PostgreSQL username
PG_PASSWORD=               # PostgreSQL password (required)
PG_DATABASE=autosec_db     # PostgreSQL database name

MONGO_URI=mongodb://autosec-mongodb:27017/autosec_logs
REDIS_URL=redis://autosec-redis:6379
RABBITMQ_URL=amqp://guest:guest@autosec-rabbitmq:5672
```

**Application Settings:**
```bash
NODE_ENV=production        # Environment (development/production)
PORT=8080                  # Backend port
LOG_LEVEL=info             # Logging level
FRONTEND_URL=http://localhost:3000  # Frontend URL for CORS
```

**External Services:**
```bash
GEOIP_DB_PATH=/app/data/geoip/GeoLite2-City.mmdb
THREAT_INTEL_API_KEY=      # Threat intelligence API key
FIREWALL_INTEGRATION_KEY=  # Firewall integration credentials
```

This installation guide provides comprehensive coverage for deploying AutoSec in various environments, from development to enterprise production deployments.