# Harbor Scanner Grype Adapter - Deployment Guide

## 🚀 Quick Start

### Using Docker Compose
```bash
# Clone the repository
git clone https://github.com/ant1freeze/harbor-scanner-grype.git
cd harbor-scanner-grype

# Deploy with Docker Compose
docker-compose up -d
```

### Using Deploy Script
```bash
# Make script executable
chmod +x deploy.sh

# Interactive deployment
./deploy.sh

# Non-interactive deployment with specific log level
./deploy.sh --log-level=info
```

## 📦 Docker Images

Available on Docker Hub:
- `ant1freeze/harbor-scanner-grype:latest`
- `ant1freeze/harbor-scanner-grype:v1.0.0`

## 🔧 Configuration

### Environment Variables
- `SCANNER_REDIS_URL` - Redis connection URL (default: `redis://redis:6379`)
- `SCANNER_LOG_LEVEL` - Log level: `error`, `warn`, `info`, `debug` (default: `info`)

### Network Requirements
- Must be connected to Harbor's network: `harbor_harbor`
- Redis service must be accessible

## 🌐 API Endpoints

- **Metadata**: `GET /api/v1/metadata`
- **Scan**: `POST /api/v1/scan`
- **Report**: `GET /api/v1/scan/{scan_request_id}/report`

## 🔍 Features

✅ **Enhanced Vulnerability Reports** - Includes `package`, `version`, and `fix_version` fields  
✅ **Grype Integration** - Uses latest Grype v0.100.0 with comprehensive vulnerability database  
✅ **Redis Queue** - Asynchronous scanning with job queue  
✅ **Auto DB Updates** - Daily vulnerability database updates via cron  
✅ **Health Checks** - Built-in health monitoring  

## 📊 Supported Formats

- **Input**: Docker images, OCI images, filesystem directories
- **Output**: Harbor Scanner API v1.1 compatible JSON reports

## 🛠️ Troubleshooting

### Check Container Status
```bash
docker ps | grep grype-adapter
```

### View Logs
```bash
docker logs -f grype-adapter
```

### Test API
```bash
curl http://localhost:8090/api/v1/metadata
```

### Change Log Level
```bash
docker exec grype-adapter env SCANNER_LOG_LEVEL=debug
docker restart grype-adapter
```

## 🔄 Updates

The vulnerability database is automatically updated daily. To manually update:

```bash
docker exec grype-adapter /usr/local/bin/update-grype-db.sh
```

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
