"""
LoadCommand model for storing Mach-O load command information.
"""

from core import db

class LoadCommand(db.Model):
    """
    Model for storing Mach-O load command information.
    """
    __tablename__ = 'load_commands'
    
    id = db.Column(db.Integer, primary_key=True)
    header_id = db.Column(db.Integer, db.ForeignKey('headers.id'), nullable=False)
    cmd_type = db.Column(db.Integer, nullable=False)
    cmd_size = db.Column(db.Integer, nullable=False)
    cmd_offset = db.Column(db.Integer, nullable=False)
    cmd_data = db.Column(db.LargeBinary)  # Serialized command-specific data
    
    def __repr__(self):
        return f"<LoadCommand type={self.cmd_type:x} for header_id {self.header_id}>" 