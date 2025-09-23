#!/bin/sh

# Start script for Grype adapter with cron for database updates

echo "Starting Grype adapter..."

# Start cron daemon in background
crond -f -l 2 &

# Start the main application
exec /home/scanner/bin/scanner-grype
