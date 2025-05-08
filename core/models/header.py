"""
Header model for storing Mach-O header information.
"""

from core import db

class Header(db.Model):
    """
    Model for storing Mach-O header information, both 32-bit and 64-bit.
    """
    __tablename__ = 'headers'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    magic_number = db.Column(db.Integer, nullable=False)
    cpu_type = db.Column(db.Integer, nullable=False)
    cpu_subtype = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.Integer, nullable=False)
    ncmds = db.Column(db.Integer, nullable=False)
    sizeofcmds = db.Column(db.Integer, nullable=False)
    flags = db.Column(db.Integer, nullable=False)
    reserved = db.Column(db.Integer)  # For 64-bit headers
    
    # Relationships
    load_commands = db.relationship('LoadCommand', backref='header', cascade='all, delete-orphan')
    
    @property
    def is_64_bit(self):
        """Check if this is a 64-bit Mach-O header based on magic number."""
        return self.magic_number in (0xfeedfacf, 0xcffaedfe)
    
    @property
    def is_little_endian(self):
        """Check if the file is little endian based on magic number."""
        return self.magic_number in (0xcefaedfe, 0xcffaedfe)
    
    def __repr__(self):
        architecture = "64-bit" if self.is_64_bit else "32-bit"
        return f"<Header {architecture} for file_id {self.file_id}>" 