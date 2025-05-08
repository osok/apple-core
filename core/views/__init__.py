"""
Import all view blueprints.
"""

from core.views.main import main_bp
from core.views.analyzer import analyzer_bp

# List all blueprints for easier import
__all__ = [
    'main_bp',
    'analyzer_bp'
] 