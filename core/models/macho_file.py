"""
MachoFile model for storing file metadata.
"""

from datetime import datetime
from core import db

class MachoFile(db.Model):
    """
    Model for storing Mach-O file information.
    """
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    md5_hash = db.Column(db.String(32), nullable=False)
    user_notes = db.Column(db.Text)
    
    # Relationships
    headers = db.relationship('Header', backref='file', cascade='all, delete-orphan')
    segments = db.relationship('Segment', backref='file', cascade='all, delete-orphan')
    edit_history = db.relationship('EditHistory', backref='file', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"<MachoFile {self.filename}>" 