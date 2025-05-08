"""
Symbol model for storing symbol table entries from Mach-O files.
"""

from core import db

class Symbol(db.Model):
    """
    Model for storing Mach-O symbol table entries.
    """
    __tablename__ = 'symbols'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.Integer, nullable=False)
    sect = db.Column(db.Integer, nullable=False)
    desc = db.Column(db.Integer, nullable=False)
    value = db.Column(db.BigInteger, nullable=False)
    is_external = db.Column(db.Boolean, default=False)
    is_debug = db.Column(db.Boolean, default=False)
    is_local = db.Column(db.Boolean, default=False)
    is_defined = db.Column(db.Boolean, default=False)
    
    # Relationship to MachoFile
    file = db.relationship('MachoFile', backref='symbols')
    
    def __repr__(self):
        return f"<Symbol {self.name}>"

class SymbolTable(db.Model):
    """
    Model for storing Mach-O symbol table metadata.
    """
    __tablename__ = 'symbol_tables'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id', ondelete='CASCADE'), nullable=False)
    symoff = db.Column(db.Integer, nullable=False)  # Offset to symbol table
    nsyms = db.Column(db.Integer, nullable=False)   # Number of symbols
    stroff = db.Column(db.Integer, nullable=False)  # Offset to string table
    strsize = db.Column(db.Integer, nullable=False) # Size of string table
    
    # Relationship to MachoFile
    file = db.relationship('MachoFile', backref='symbol_tables')
    
    def __repr__(self):
        return f"<SymbolTable file_id={self.file_id}, nsyms={self.nsyms}>"

class DynamicSymbolTable(db.Model):
    """
    Model for storing Mach-O dynamic symbol table metadata.
    """
    __tablename__ = 'dynamic_symbol_tables'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id', ondelete='CASCADE'), nullable=False)
    ilocalsym = db.Column(db.Integer, nullable=False)  # Index to local symbols
    nlocalsym = db.Column(db.Integer, nullable=False)  # Number of local symbols
    iextdefsym = db.Column(db.Integer, nullable=False) # Index to externally defined symbols
    nextdefsym = db.Column(db.Integer, nullable=False) # Number of externally defined symbols
    iundefsym = db.Column(db.Integer, nullable=False)  # Index to undefined symbols
    nundefsym = db.Column(db.Integer, nullable=False)  # Number of undefined symbols
    
    # Indirect symbol table fields
    indirectsymoff = db.Column(db.Integer, nullable=True)  # Offset to indirect symbol table
    nindirectsyms = db.Column(db.Integer, nullable=True)   # Number of indirect symbols
    
    # Relationship to MachoFile
    file = db.relationship('MachoFile', backref='dynamic_symbol_tables')
    
    def __repr__(self):
        return f"<DynamicSymbolTable file_id={self.file_id}>" 