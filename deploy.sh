#!/bin/bash

# Harbor Scanner Grype Adapter Deployment Script
# This script ensures the adapter is properly deployed with correct network settings

set -e

# Configuration
CONTAINER_NAME="grype-adapter"
IMAGE_NAME="hamster5133/harbor-scanner-grype:latest"
NETWORK_NAME="harbor_harbor"
PORT="8090"
REDIS_URL="redis://redis:6379"

echo "🚀 Deploying Harbor Scanner Grype Adapter..."

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
echo "🏃 Starting container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    -e SCANNER_REDIS_URL="$REDIS_URL" \
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
echo ""
echo "🌐 API endpoint: http://localhost:$PORT"
