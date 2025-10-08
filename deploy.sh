#!/bin/bash

# Harbor Scanner Grype Adapter Deployment Script
# This script ensures the adapter is properly deployed with correct network settings
#
# Usage:
#   ./deploy.sh                    # Interactive mode
#   ./deploy.sh --log-level=info   # Non-interactive mode
#   ./deploy.sh --help             # Show help

set -e

# Parse command line arguments
LOG_LEVEL=""
NON_INTERACTIVE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --log-level=*)
            LOG_LEVEL="${1#*=}"
            NON_INTERACTIVE=true
            shift
            ;;
        --help|-h)
            echo "Harbor Scanner Grype Adapter Deployment Script"
            echo ""
            echo "Usage:"
            echo "  $0                           # Interactive mode"
            echo "  $0 --log-level=LEVEL         # Non-interactive mode"
            echo "  $0 --help                    # Show this help"
            echo ""
            echo "Log levels:"
            echo "  error   - Only errors (minimal logs)"
            echo "  warn    - Warnings and errors"
            echo "  info    - Info, warnings and errors (recommended)"
            echo "  debug   - All logs (verbose, for troubleshooting)"
            echo ""
            echo "Examples:"
            echo "  $0 --log-level=info"
            echo "  $0 --log-level=debug"
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Configuration
CONTAINER_NAME="grype-adapter"
IMAGE_NAME="ant1freeze/harbor-scanner-grype:latest"
NETWORK_NAME="harbor_harbor"
PORT="8090"
REDIS_URL="redis://redis:6379"

echo "🚀 Deploying Harbor Scanner Grype Adapter..."

# Log level selection
if [ "$NON_INTERACTIVE" = true ]; then
    # Validate provided log level
    case $LOG_LEVEL in
        error|warn|info|debug)
            echo "📝 Using log level: $LOG_LEVEL"
            ;;
        *)
            echo "❌ Invalid log level: $LOG_LEVEL"
            echo "Valid levels: error, warn, info, debug"
            exit 1
            ;;
    esac
else
    # Interactive log level selection
    echo ""
    echo "📊 Select log level:"
    echo "  1) error   - Only errors (minimal logs)"
    echo "  2) warn    - Warnings and errors"
    echo "  3) info    - Info, warnings and errors (recommended)"
    echo "  4) debug   - All logs (verbose, for troubleshooting)"
    echo ""
    read -p "Enter choice [1-4] (default: 3): " LOG_CHOICE

    case $LOG_CHOICE in
        1)
            LOG_LEVEL="error"
            ;;
        2)
            LOG_LEVEL="warn"
            ;;
        3|"")
            LOG_LEVEL="info"
            ;;
        4)
            LOG_LEVEL="debug"
            ;;
        *)
            echo "❌ Invalid choice. Using default: info"
            LOG_LEVEL="info"
            ;;
    esac

    echo "📝 Selected log level: $LOG_LEVEL"
fi

# Check if Harbor network exists
if ! docker network ls | grep -q "$NETWORK_NAME"; then
    echo "❌ Network '$NETWORK_NAME' not found!"
    echo "Available networks:"
    docker network ls
    echo ""
    echo "Please ensure Harbor is running and the network exists."
    exit 1
fi

# Stop and remove existing container if it exists
if docker ps -a | grep -q "$CONTAINER_NAME"; then
    echo "🛑 Stopping existing container..."
    docker stop "$CONTAINER_NAME" || true
    docker rm "$CONTAINER_NAME" || true
fi

# Pull latest image
echo "📥 Pulling latest image..."
docker pull "$IMAGE_NAME"

# Run the container with proper settings
echo "🏃 Starting container with log level: $LOG_LEVEL..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    -e SCANNER_REDIS_URL="$REDIS_URL" \
    -e SCANNER_LOG_LEVEL="$LOG_LEVEL" \
    -p "$PORT:$PORT" \
    --restart unless-stopped \
    "$IMAGE_NAME"

# Wait a moment for container to start
sleep 3

# Check container status
echo "📊 Container status:"
docker ps | grep "$CONTAINER_NAME"

# Check logs
echo "📋 Recent logs:"
docker logs --tail 10 "$CONTAINER_NAME"

# Test API endpoint
echo "🔍 Testing API endpoint..."
if curl -s -f "http://localhost:$PORT/api/v1/metadata" > /dev/null; then
    echo "✅ API is responding correctly!"
else
    echo "❌ API is not responding. Check logs:"
    docker logs "$CONTAINER_NAME"
fi

echo "🎉 Deployment completed!"
echo ""
echo "📝 Useful commands:"
echo "  View logs:     docker logs -f $CONTAINER_NAME"
echo "  Stop:          docker stop $CONTAINER_NAME"
echo "  Restart:       docker restart $CONTAINER_NAME"
echo "  Remove:        docker rm -f $CONTAINER_NAME"
echo "  Change logs:   docker exec $CONTAINER_NAME env SCANNER_LOG_LEVEL=debug"
echo ""
echo "🌐 API endpoint: http://localhost:$PORT"
echo "📊 Current log level: $LOG_LEVEL"
echo ""
echo "💡 To change log level without redeployment:"
echo "  docker exec $CONTAINER_NAME env SCANNER_LOG_LEVEL=debug"
echo "  docker restart $CONTAINER_NAME"
