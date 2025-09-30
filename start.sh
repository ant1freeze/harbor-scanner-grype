#!/bin/sh

# Start script for Grype adapter with cron for database updates

echo "Starting Grype adapter..."

# Start cron daemon in background (run as root to have proper permissions)
crond -f -l 2 &

# Start the main application as scanner user
exec /home/scanner/bin/scanner-grype
