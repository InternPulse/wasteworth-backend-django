#!/usr/bin/env bash
# Build script for Render deployment
# This script runs automatically during deployment

set -o errexit  # Exit on error

echo "======================================"
echo "Starting Render Build Process"
echo "======================================"

# Install Python dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --no-input

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --no-input

# Show migration status
echo "Checking migration status..."
python manage.py showmigrations

echo "======================================"
echo "Build completed successfully!"
echo "======================================"
