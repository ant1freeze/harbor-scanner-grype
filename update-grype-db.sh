#!/bin/sh

# Script to update Grype vulnerability database
# This script should be run daily at 00:00 via cron

echo "$(date): Starting Grype database update..."

# Update the vulnerability database
/usr/local/bin/grype db update

if [ $? -eq 0 ]; then
    echo "$(date): Grype database updated successfully"
else
    echo "$(date): ERROR: Failed to update Grype database"
    exit 1
fi

echo "$(date): Grype database update completed"
