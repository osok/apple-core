"""
Segment model for storing Mach-O segment information.
"""

from core import db

class Segment(db.Model):
    """
    Model for storing Mach-O segment information, both 32-bit and 64-bit.
    """
    __tablename__ = 'segments'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    segname = db.Column(db.String(16), nullable=False)
    vmaddr = db.Column(db.BigInteger, nullable=False)
    vmsize = db.Column(db.BigInteger, nullable=False)
    fileoff = db.Column(db.BigInteger, nullable=False)
    filesize = db.Column(db.BigInteger, nullable=False)
    maxprot = db.Column(db.Integer, nullable=False)
    initprot = db.Column(db.Integer, nullable=False)
    nsects = db.Column(db.Integer, nullable=False)
    flags = db.Column(db.Integer, nullable=False)
    
    # Relationships
    sections = db.relationship('Section', backref='segment', cascade='all, delete-orphan')
    
    @property
    def protection_string(self):
        """Convert protection flags to readable string (rwx)."""
        result = ""
        if self.initprot & 0x01:  # VM_PROT_READ
            result += "r"
        else:
            result += "-"
        if self.initprot & 0x02:  # VM_PROT_WRITE
            result += "w"
        else:
            result += "-"
        if self.initprot & 0x04:  # VM_PROT_EXECUTE
            result += "x"
        else:
            result += "-"
        return result
    
    def __repr__(self):
        return f"<Segment {self.segname} at {self.vmaddr:x}>" 