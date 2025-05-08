#!/bin/bash

# Create uploads directory if it doesn't exist
mkdir -p uploads

# Set Flask environment variables
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_DEBUG=1

# Run the Flask application
flask run 