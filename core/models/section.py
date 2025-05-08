"""
Section model for storing Mach-O section information.
"""

from core import db

class Section(db.Model):
    """
    Model for storing Mach-O section information.
    """
    __tablename__ = 'sections'
    
    id = db.Column(db.Integer, primary_key=True)
    segment_id = db.Column(db.Integer, db.ForeignKey('segments.id'), nullable=False)
    sectname = db.Column(db.String(16), nullable=False)
    segname = db.Column(db.String(16), nullable=False)
    addr = db.Column(db.BigInteger, nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    offset = db.Column(db.Integer, nullable=False)
    align = db.Column(db.Integer, nullable=False)
    flags = db.Column(db.Integer, nullable=False)
    
    @property
    def type_string(self):
        """Convert section type flags to readable string."""
        section_types = {
            0x0: "Regular",
            0x1: "ZeroFill",
            0x2: "CStringLiterals",
            0x3: "4ByteLiterals",
            0x4: "8ByteLiterals",
            0x5: "LiteralPointers",
            0x6: "NonLazySymbolPointers",
            0x7: "LazySymbolPointers",
            0x8: "SymbolStubs",
            0x9: "ModInitFuncs",
            0xA: "ModTermFuncs",
            0xB: "Coalesced",
            0xC: "GBZeroFill",
            0xD: "Interposing",
            0xE: "16ByteLiterals",
            0xF: "DtraceDOF",
            0x10: "LazyDylibSymbolPointers",
            0x11: "ThreadLocalRegular",
            0x12: "ThreadLocalZerofill",
            0x13: "ThreadLocalVariables",
            0x14: "ThreadLocalVariablePointers",
            0x15: "ThreadLocalInitFunctionPointers"
        }
        
        # The type is stored in the lowest 8 bits of flags
        section_type = self.flags & 0xFF
        return section_types.get(section_type, f"Unknown ({section_type:x})")
    
    def __repr__(self):
        return f"<Section {self.sectname} in {self.segname} at {self.addr:x}>" 