"""
EditHistory model for tracking file edit operations.
"""

from datetime import datetime, UTC
from core import db

class EditHistory(db.Model):
    """
    Model for tracking edit operations on Mach-O files.
    """
    __tablename__ = 'edit_history'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    edit_timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    edit_type = db.Column(db.String(20), nullable=False)  # 'modify', 'add', 'delete'
    target_type = db.Column(db.String(50), nullable=False)  # 'header', 'section', 'segment', etc.
    target_id = db.Column(db.Integer, nullable=False)
    before_value = db.Column(db.LargeBinary)
    after_value = db.Column(db.LargeBinary)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'applied', 'reverted', 'failed'
    
    def __repr__(self):
        return f"<EditHistory {self.edit_type} on {self.target_type} at {self.edit_timestamp}>" 