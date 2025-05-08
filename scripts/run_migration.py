#!/usr/bin/env python3
"""
Script to run database migrations for Apple-Core.
"""

import os
import sys
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

# Import project modules
from core import db, create_app

def run_migrations():
    """Run all pending Alembic migrations."""
    print("Running database migrations...")
    
    # Create the Flask app context
    app = create_app()
    
    with app.app_context():
        # Use subprocess to run alembic command with config file
        alembic_cmd = ["alembic", "-c", "migrations/alembic.ini", "upgrade", "head"]
        try:
            subprocess.run(alembic_cmd, check=True, cwd=str(project_root))
            print("Migrations completed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"Error running migrations: {e}")
            return False
    
    return True

if __name__ == "__main__":
    success = run_migrations()
    sys.exit(0 if success else 1) 