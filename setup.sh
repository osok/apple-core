#!/bin/bash

echo "Setting up Apple-Core Mach-O Analyzer..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p uploads
mkdir -p instance

# Initialize database
echo "Initializing database..."
export FLASK_APP=app.py
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

echo "Setup complete! Run './run.sh' to start the application." 