"""
Configuration settings for the Apple-Core Mach-O Analyzer application.
"""

import os

class Config:
    """Base configuration."""
    # Secret key for session management
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-for-development-only'
    
    # SQLite database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'apple-core.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload folder for binary files
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or \
        os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    
    # Ensure upload folder exists
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    # Allowed file extensions for upload
    ALLOWED_EXTENSIONS = {'macho', 'bin', 'dylib', 'so', 'o', 'bundle', 'app'}
    
    # Maximum file size for upload (50 MB)
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    

class ProductionConfig(Config):
    """Production configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    DEBUG = False


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 