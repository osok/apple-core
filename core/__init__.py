"""
Core module initialization for Apple-Core Mach-O Analyzer.
Implements the application factory pattern.
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()

@login_manager.user_loader
def load_user(user_id):
    # Since we don't have user authentication, return None
    return None

def create_app(config_name=None):
    """
    Application factory function that creates and configures the Flask app.
    
    Args:
        config_name (str): The configuration to use (default, development, testing, production)
    
    Returns:
        Flask: The configured Flask application
    """
    # Create the Flask application
    app = Flask(__name__, 
                static_folder='../static',
                template_folder='../templates')
    
    # Configure app from config.py
    from config import config
    config_name = config_name or os.environ.get('FLASK_CONFIG', 'default')
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Register blueprints
    from core.views.main import main_bp
    app.register_blueprint(main_bp)
    
    from core.views.analyzer import analyzer_bp
    app.register_blueprint(analyzer_bp, url_prefix='/analyzer')
    
    # Ensure upload directory exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Shell context for flask cli
    @app.shell_context_processor
    def make_shell_context():
        from core.models.macho_file import MachoFile
        from core.models.header import Header
        from core.models.segment import Segment
        from core.models.section import Section
        
        return {
            'db': db, 
            'MachoFile': MachoFile,
            'Header': Header,
            'Segment': Segment,
            'Section': Section
        }
    
    return app 