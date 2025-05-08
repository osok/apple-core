"""
Tests for application initialization.
"""

import os
import pytest
from flask import Flask
from core import create_app, db
from core.models.macho_file import MachoFile


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = create_app('testing')
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    yield app
    
    # Clean up
    with app.app_context():
        db.drop_all()


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


def test_app_exists(app):
    """Test that the app exists."""
    assert app is not None


def test_app_is_testing(app):
    """Test that the app is in testing mode."""
    assert app.config['TESTING'] is True
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'


def test_index_page(client):
    """Test that the index page loads."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Apple-Core Mach-O Analyzer' in response.data


def test_db_setup(app):
    """Test that the database tables are created."""
    with app.app_context():
        # Check that we can create and query a model
        test_file = MachoFile(
            filename='test.bin',
            filepath='/tmp/test.bin',
            file_size=1024,
            md5_hash='deadbeef'
        )
        db.session.add(test_file)
        db.session.commit()
        
        # Query the file
        result = MachoFile.query.filter_by(filename='test.bin').first()
        assert result is not None
        assert result.filename == 'test.bin'
        assert result.file_size == 1024
        assert result.md5_hash == 'deadbeef' 