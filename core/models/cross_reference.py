"""
Cross-reference model for mapping relationships between symbols and sections.
"""

from core import db

class CrossReference(db.Model):
    """
    Model for storing cross-references between symbols and their references.
    """
    __tablename__ = 'cross_references'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id', ondelete='CASCADE'), nullable=False)
    
    # Source of the reference
    source_type = db.Column(db.String(20), nullable=False)  # 'symbol' or 'section'
    source_id = db.Column(db.Integer, nullable=False)      # ID of the symbol or section
    
    # Target of the reference
    target_type = db.Column(db.String(20), nullable=False)  # 'symbol' or 'section'
    target_id = db.Column(db.Integer, nullable=False)      # ID of the symbol or section
    
    # Reference details
    offset = db.Column(db.BigInteger, nullable=True)       # Offset within the source
    reference_type = db.Column(db.String(50), nullable=True)  # Type of reference (call, jump, data)
    
    # Relationship to MachoFile
    file = db.relationship('MachoFile', backref='cross_references')
    
    def __repr__(self):
        return f"<CrossReference {self.source_type}:{self.source_id} -> {self.target_type}:{self.target_id}>" 