#!/usr/bin/env python3
"""
Apple-Core: Mach-O File Analyzer
Entry point for the Flask application.
"""

from core import create_app

# Create the Flask application instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True) 