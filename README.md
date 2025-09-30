# Harbor Scanner Adapter for Grype

A Harbor Scanner Adapter that integrates [Grype](https://github.com/anchore/grype) vulnerability scanner with [Harbor](https://goharbor.io/) container registry.

## Overview

This project provides a Harbor Scanner Adapter that allows Harbor to use Grype for vulnerability scanning of container images. It implements the Harbor Scanner Adapter API v1.1 and provides real-time vulnerability scanning capabilities.

## Features

- ✅ **Real Grype Integration**: Uses actual Grype binary for vulnerability scanning
- ✅ **Harbor API v1.1 Compatible**: Implements the complete Harbor Scanner Adapter API
- ✅ **Redis-based Job Queue**: Asynchronous scanning with Redis backend
- ✅ **Docker Support**: Easy deployment with Docker containers
- ✅ **Real Vulnerability Database**: Uses Grype's up-to-date vulnerability database
- ✅ **Multiple Severity Levels**: Supports Critical, High, Medium, Low, and Unknown severity levels
- ✅ **Authentication Support**: Handles Harbor registry authentication

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Harbor registry running
- Redis server

### 1. Build the Scanner

```bash
# Clone the repository
git clone https://github.com/hamster513/harbor-scanner-grype.git
cd harbor-scanner-grype

# Build the Docker image
docker build -t harbor-scanner-grype:latest .
```

### 2. Run with Docker Compose

```yaml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  harbor-scanner-grype:
    image: harbor-scanner-grype:latest
    ports:
      - "8090:8090"
    environment:
      - SCANNER_REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    networks:
      - harbor_harbor  # Connect to Harbor network
```

### 3. Configure Harbor

1. In Harbor UI, go to **Administration** → **Interrogation Services** → **Scanners**
2. Click **New Scanner**
3. Enter the scanner endpoint: `http://your-scanner-host:8090`
4. Test the connection and save

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SCANNER_REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `SCANNER_API_SERVER_ADDR` | API server address | `:8090` |
| `SCANNER_GRYPE_CACHE_DIR` | Grype cache directory | `/home/scanner/.cache/grype` |
| `SCANNER_GRYPE_DEBUG_MODE` | Enable debug mode | `false` |
| `SCANNER_GRYPE_SEVERITY` | Severity levels to scan | `Unknown,Low,Medium,High,Critical` |

## API Endpoints

The scanner implements the Harbor Scanner Adapter API v1.1:

- `GET /api/v1/metadata` - Scanner metadata and capabilities
- `POST /api/v1/scan` - Start vulnerability scan
- `GET /api/v1/scan/{scan_request_id}/report` - Get scan report

## Development

### Building from Source

```bash
# Install Go 1.21+
go mod download
go build -o scanner-grype ./cmd/scanner-grype
```

### Docker Build

```bash
# Build for Linux AMD64
GOOS=linux GOARCH=amd64 go build -o scanner-grype-linux ./cmd/scanner-grype
docker build -t harbor-scanner-grype:latest .
```

## Integration with Harbor

### Network Configuration

For proper integration with Harbor, ensure the scanner container is connected to the Harbor network:

```bash
# Connect to Harbor network
docker network connect harbor_harbor your-scanner-container

# Add hosts entry for Harbor registry
docker exec your-scanner-container sh -c 'echo "192.168.6.131 harbor.corp.local" >> /etc/hosts'
```

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```
   Error: dial tcp [::1]:6379: connect: connection refused
   ```
   **Solution**: Ensure Redis is running and `SCANNER_REDIS_URL` is correctly configured.

2. **Harbor Registry Access Denied**
   ```
   ERROR: UNAUTHORIZED: unauthorized to access repository
   ```
   **Solution**: Verify network connectivity and authentication credentials.

### Debug Mode

Enable debug logging:

```bash
docker run -e SCANNER_GRYPE_DEBUG_MODE=true harbor-scanner-grype:latest
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Harbor](https://goharbor.io/) - Container registry platform
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner
- [Harbor Scanner Trivy](https://github.com/aquasecurity/harbor-scanner-trivy) - Reference implementation
