# AutoSec Enterprise Deployment Guide

This guide covers the complete deployment of AutoSec enterprise features including Kubernetes, advanced analytics, and enterprise security capabilities.

## Prerequisites

### System Requirements
- Kubernetes cluster v1.24+
- Helm v3.8+
- Persistent storage with 500GB+ capacity
- 16+ CPU cores and 32GB+ RAM across nodes
- Network load balancer support

### Required Software
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install cert-manager (for TLS certificates)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

## 1. Kubernetes Infrastructure Deployment

### Option A: Helm Chart Deployment (Recommended)

```bash
# Add AutoSec Helm repository (placeholder - would be real repository)
helm repo add autosec https://charts.autosec.io
helm repo update

# Create namespace
kubectl create namespace autosec

# Create secrets
kubectl create secret generic autosec-secrets \
  --from-literal=jwt-secret=$(openssl rand -base64 64) \
  --from-literal=postgres-password=$(openssl rand -base64 32) \
  --from-literal=mongo-password=$(openssl rand -base64 32) \
  --from-literal=redis-password=$(openssl rand -base64 32) \
  --from-literal=rabbitmq-password=$(openssl rand -base64 32) \
  -n autosec

# Deploy with custom values
helm install autosec autosec/autosec-platform \
  --namespace autosec \
  --set global.domain=your-domain.com \
  --set backend.replicaCount=3 \
  --set frontend.replicaCount=2 \
  --set postgresql.primary.persistence.size=50Gi \
  --set mongodb.persistence.size=100Gi \
  -f custom-values.yaml
```

### Option B: Direct Kubernetes Manifests

```bash
# Deploy in order
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/mongodb.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/rabbitmq.yaml

# Wait for databases to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n autosec --timeout=300s
kubectl wait --for=condition=ready pod -l app=mongodb -n autosec --timeout=300s

# Deploy application
kubectl apply -f k8s/backend.yaml
kubectl apply -f k8s/frontend.yaml
kubectl apply -f k8s/ingress.yaml

# Apply security policies
kubectl apply -f k8s/networkpolicy.yaml
kubectl apply -f k8s/poddisruptionbudget.yaml
```

## 2. Monitoring and Observability Setup

### Prometheus and Grafana

```bash
# Install Prometheus Operator
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  -f monitoring/prometheus/values.yaml

# Apply AutoSec monitoring configurations
kubectl apply -f monitoring/servicemonitor.yaml
kubectl apply -f monitoring/prometheus/alerts.yaml

# Import AutoSec Grafana dashboards
kubectl create configmap autosec-dashboards \
  --from-file=monitoring/grafana/dashboards/ \
  -n monitoring
```

### ELK Stack (Optional)

```bash
# Install Elasticsearch
helm repo add elastic https://helm.elastic.co
helm install elasticsearch elastic/elasticsearch --namespace logging --create-namespace

# Install Kibana
helm install kibana elastic/kibana --namespace logging

# Install Filebeat for log collection
helm install filebeat elastic/filebeat --namespace logging
```

## 3. Service Mesh Integration (Istio)

```bash
# Install Istio
curl -L https://istio.io/downloadIstio | sh -
export PATH="$PATH:$PWD/istio-1.19.0/bin"

# Install Istio control plane
istioctl install --set values.defaultRevision=default

# Enable sidecar injection for AutoSec namespace
kubectl label namespace autosec istio-injection=enabled

# Apply Istio configurations
kubectl apply -f istio/gateway.yaml
kubectl apply -f istio/virtualservice.yaml
kubectl apply -f istio/destinationrules.yaml
```

## 4. Enterprise Security Features

### Zero Trust Network Access (ZTNA)

The ZTNA service is automatically deployed with the backend. Configure policies:

```javascript
// Example ZTNA policy configuration
const ztnaPolicies = {
  high_sensitivity_resources: {
    requiredTrustLevel: 80,
    allowConditionalAccess: false,
    maxSessionDuration: 2 * 60 * 60 * 1000, // 2 hours
    additionalRequirements: ['mfa', 'device_compliance']
  }
};
```

### Cloud Security Posture Management (CSPM)

Configure cloud provider credentials:

```bash
# AWS credentials (using service account)
kubectl create secret generic aws-credentials \
  --from-literal=access-key-id=$AWS_ACCESS_KEY_ID \
  --from-literal=secret-access-key=$AWS_SECRET_ACCESS_KEY \
  -n autosec

# Azure credentials
kubectl create secret generic azure-credentials \
  --from-literal=client-id=$AZURE_CLIENT_ID \
  --from-literal=client-secret=$AZURE_CLIENT_SECRET \
  --from-literal=tenant-id=$AZURE_TENANT_ID \
  -n autosec
```

### Container Security

Deploy Falco for runtime protection:

```bash
# Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco-system \
  --create-namespace \
  --set falco.webserver.enabled=true \
  --set falco.webserver.k8sAuditEndpoint.enabled=true
```

### Data Loss Prevention (DLP)

DLP service monitors network traffic and file operations automatically. Configure policies via API:

```bash
# Example DLP policy creation
curl -X POST http://autosec.your-domain.com/api/dlp/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PII Protection",
    "conditions": {
      "dataTypes": ["pii", "credentials"],
      "sensitivityScore": 50
    },
    "actions": [
      {"type": "quarantine"},
      {"type": "notify", "recipients": ["security@company.com"]}
    ]
  }'
```

### Advanced Deception Technology

Deploy honeypots and honeytokens:

```bash
# Example honeytoken deployment via API
curl -X POST http://autosec.your-domain.com/api/deception/honeytokens \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "credential",
    "name": "Database Admin Credentials",
    "location": "/opt/app/config/db_backup.conf",
    "alertThreshold": 1
  }'
```

## 5. Advanced Analytics and Reporting

### Dashboard Customization

Access the dashboard customization interface at `https://autosec.your-domain.com/dashboards/customize`

Available widget types:
- Threat Summary
- Geographic Threat Map
- 3D Network Topology
- ML Model Performance
- Executive Summary
- Real-time Alerts
- Threat Intelligence Feed
- Network Traffic 3D Visualization

### Report Generation

Schedule automated reports:

```bash
# Schedule weekly security summary
curl -X POST http://autosec.your-domain.com/api/reports/schedule \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "security_summary",
    "schedule": {
      "cron": "0 8 * * 1",
      "timezone": "UTC"
    },
    "parameters": {
      "timeRange": "7d",
      "format": "pdf",
      "includeCharts": true
    },
    "delivery": {
      "method": "email",
      "recipients": ["executives@company.com"]
    }
  }'
```

## 6. High Availability Configuration

### Database High Availability

```yaml
# PostgreSQL HA configuration
postgresql:
  primary:
    resources:
      limits:
        cpu: 2000m
        memory: 4Gi
    persistence:
      size: 100Gi
  readReplicas:
    replicaCount: 2
    resources:
      limits:
        cpu: 1000m
        memory: 2Gi

# MongoDB Replica Set
mongodb:
  replicaCount: 3
  arbiter:
    enabled: true
  persistence:
    size: 200Gi
```

### Application High Availability

```yaml
# Backend HA
backend:
  replicaCount: 5
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
    targetCPUUtilizationPercentage: 70

# Frontend HA  
frontend:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
```

## 7. Backup and Disaster Recovery

### Database Backups

```bash
# Automated PostgreSQL backups
kubectl create cronjob postgres-backup \
  --image=postgres:15 \
  --schedule="0 2 * * *" \
  --restart=OnFailure \
  -- /bin/bash -c "pg_dump -h postgres -U autosec -d autosec | gzip > /backup/postgres-$(date +%Y%m%d).sql.gz"

# MongoDB backups
kubectl create cronjob mongodb-backup \
  --image=mongo:7.0 \
  --schedule="0 3 * * *" \
  --restart=OnFailure \
  -- /bin/bash -c "mongodump --host mongodb --db autosec_logs --gzip --archive=/backup/mongodb-$(date +%Y%m%d).gz"
```

### Application State Backups

```bash
# Backup persistent volumes
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: backup-script
data:
  backup.sh: |
    #!/bin/bash
    kubectl get pv -o yaml > /backup/persistent-volumes-$(date +%Y%m%d).yaml
    kubectl get pvc -n autosec -o yaml > /backup/persistent-volume-claims-$(date +%Y%m%d).yaml
EOF
```

## 8. Security Hardening

### Network Security

```bash
# Apply network policies
kubectl apply -f k8s/networkpolicy.yaml

# Configure Istio security policies
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: autosec
spec:
  mtls:
    mode: STRICT
EOF
```

### Pod Security Standards

```bash
# Apply Pod Security Standards
kubectl label namespace autosec \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

## 9. Monitoring and Alerting

### Health Checks

```bash
# Check deployment status
kubectl get all -n autosec

# Check service health
curl -f http://autosec.your-domain.com/health

# Check metrics endpoint
curl http://autosec.your-domain.com/metrics
```

### Alerting Configuration

Configure alerts in Prometheus:

```yaml
groups:
- name: autosec.critical
  rules:
  - alert: AutoSecDown
    expr: up{job="autosec-backend"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "AutoSec backend is down"
      
  - alert: HighMemoryUsage
    expr: container_memory_usage_bytes{namespace="autosec"} / container_spec_memory_limit_bytes > 0.9
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage in AutoSec"
```

## 10. Scaling and Performance

### Horizontal Pod Autoscaling

HPA is automatically configured. Monitor scaling:

```bash
# Check HPA status
kubectl get hpa -n autosec

# View scaling events
kubectl describe hpa autosec-backend-hpa -n autosec
```

### Performance Tuning

```yaml
# Optimized resource allocation
backend:
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 4000m
      memory: 8Gi
  
  jvm:
    heapSize: "4g"
    gcSettings: "-XX:+UseG1GC -XX:MaxGCPauseMillis=200"
```

## 11. Maintenance and Updates

### Rolling Updates

```bash
# Update backend image
kubectl set image deployment/autosec-backend backend=autosec/backend:1.1.0 -n autosec

# Check rollout status
kubectl rollout status deployment/autosec-backend -n autosec

# Rollback if needed
kubectl rollout undo deployment/autosec-backend -n autosec
```

### Database Migrations

```bash
# Run database migrations
kubectl create job db-migration --from=cronjob/db-migration -n autosec

# Check migration status
kubectl logs job/db-migration -n autosec
```

## 12. Troubleshooting

### Common Issues

**Pods not starting:**
```bash
kubectl describe pod <pod-name> -n autosec
kubectl logs <pod-name> -n autosec
```

**Database connection issues:**
```bash
kubectl exec -it deployment/autosec-backend -n autosec -- /bin/bash
# Test database connectivity from within pod
```

**Performance issues:**
```bash
# Check resource usage
kubectl top pods -n autosec
kubectl top nodes

# Check metrics
curl http://autosec.your-domain.com/metrics | grep -E "(cpu|memory|requests)"
```

### Support and Documentation

- **Architecture Documentation**: `/docs/developer-guide/architecture.md`
- **API Documentation**: `https://autosec.your-domain.com/api/docs`
- **Security Guide**: `/docs/security/architecture.md`
- **Monitoring Runbook**: `/docs/operations/monitoring.md`

For additional support, check the logs and metrics, and refer to the comprehensive documentation in the `/docs` directory.