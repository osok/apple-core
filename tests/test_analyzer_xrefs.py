"""
Tests for the cross-reference identification functionality in the analyzer module.
"""

import unittest
from unittest.mock import patch
from core.services.analyzer_service import identify_cross_references, get_cross_reference_data
from core.models.macho_file import MachoFile
from core.models.segment import Segment
from core.models.section import Section
from core.models.symbol import Symbol
from core.models.cross_reference import CrossReference
from app import create_app
from core import db

class TestCrossReferenceIdentification(unittest.TestCase):
    """Test cases for cross-reference identification functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
        # Create a test file record
        self.test_file = MachoFile(
            filename="test.bin",
            filepath="/path/to/test.bin",
            file_size=1024,
            md5_hash="testmd5hash",
            file_type="MH_EXECUTE",
            architecture="Intel x86-64"
        )
        db.session.add(self.test_file)
        db.session.commit()
        self.file_id = self.test_file.id
        
        # Create a test segment and section
        self.test_segment = Segment(
            file_id=self.file_id,
            segname="__TEXT",
            vmaddr=0x100000000,
            vmsize=0x1000,
            fileoff=0,
            filesize=0x1000,
            maxprot=7,
            initprot=5,
            nsects=1,
            flags=0
        )
        db.session.add(self.test_segment)
        db.session.commit()
        
        self.test_section = Section(
            segment_id=self.test_segment.id,
            sectname="__text",
            segname="__TEXT",
            addr=0x100000100,
            size=0x500,
            offset=0x100,
            align=4,
            flags=0x80000400
        )
        db.session.add(self.test_section)
        
        # Create some test symbols
        self.symbols = [
            Symbol(
                file_id=self.file_id,
                name="_main",
                type=0x0F,
                sect=1,
                desc=0,
                value=0x100000100,  # Start of the section
                is_external=True,
                is_debug=False,
                is_local=False,
                is_defined=True
            ),
            Symbol(
                file_id=self.file_id,
                name="_helper_func",
                type=0x0F,
                sect=1,
                desc=0,
                value=0x100000200,  # Inside the section
                is_external=True,
                is_debug=False,
                is_local=False,
                is_defined=True
            ),
            Symbol(
                file_id=self.file_id,
                name="_external_func",
                type=0x01,
                sect=0,
                desc=0,
                value=0,
                is_external=True,
                is_debug=False,
                is_local=False,
                is_defined=False
            ),
            Symbol(
                file_id=self.file_id,
                name="_data_ref",
                type=0x0F,
                sect=1,
                desc=0,
                value=0x100000200,  # Same as _helper_func (for reference testing)
                is_external=False,
                is_debug=False,
                is_local=True,
                is_defined=True
            )
        ]
        
        for symbol in self.symbols:
            db.session.add(symbol)
        
        db.session.commit()
        
    def tearDown(self):
        """Clean up after tests."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    def test_identify_cross_references(self):
        """Test identifying cross-references between symbols and sections."""
        # Call the function
        xref_count = identify_cross_references(self.file_id)
        
        # Verify cross-references were created
        self.assertEqual(xref_count, 5)  # 3 section-to-symbol + 2 symbol-to-symbol
        
        # Verify section-to-symbol references
        section_to_symbol_xrefs = CrossReference.query.filter_by(
            file_id=self.file_id,
            source_type='section',
            target_type='symbol'
        ).all()
        
        self.assertEqual(len(section_to_symbol_xrefs), 3)
        
        # Check specific cross-references
        main_xref = CrossReference.query.filter_by(
            file_id=self.file_id,
            source_type='section',
            target_type='symbol',
            target_id=self.symbols[0].id  # _main
        ).first()
        
        self.assertIsNotNone(main_xref)
        self.assertEqual(main_xref.source_id, self.test_section.id)
        self.assertEqual(main_xref.offset, 0)  # _main is at the start of the section
        self.assertEqual(main_xref.reference_type, 'contains')
        
        # Verify symbol-to-symbol references
        symbol_to_symbol_xrefs = CrossReference.query.filter_by(
            file_id=self.file_id,
            source_type='symbol',
            target_type='symbol'
        ).all()
        
        self.assertEqual(len(symbol_to_symbol_xrefs), 2)
        
        # Check specific symbol-to-symbol cross-reference
        sym_xref = CrossReference.query.filter_by(
            file_id=self.file_id,
            source_type='symbol',
            target_type='symbol',
            source_id=self.symbols[3].id  # _data_ref
        ).first()
        
        self.assertIsNotNone(sym_xref)
        self.assertEqual(sym_xref.target_id, self.symbols[1].id)  # _helper_func
        self.assertEqual(sym_xref.reference_type, 'references')
    
    def test_identify_cross_references_no_file(self):
        """Test handling when file doesn't exist."""
        result = identify_cross_references(999)  # Non-existent file ID
        self.assertEqual(result, 0)
    
    def test_get_cross_reference_data(self):
        """Test retrieving cross-reference data."""
        # First create some cross-references
        identify_cross_references(self.file_id)
        
        # Get cross-reference data
        data = get_cross_reference_data(self.file_id)
        
        # Verify data
        self.assertIsNotNone(data)
        self.assertEqual(data['file'].id, self.file_id)
        self.assertEqual(data['count'], 5)
        
        # Check cross-reference details
        for xref in data['xrefs']:
            # Check source and target names
            if xref['source_type'] == 'section':
                self.assertIn('__TEXT', xref['source_name'])
            elif xref['source_type'] == 'symbol':
                self.assertIn('_', xref['source_name'])
                
            if xref['target_type'] == 'symbol':
                self.assertIn('_', xref['target_name'])
    
    def test_get_cross_reference_data_no_file(self):
        """Test handling when file doesn't exist."""
        result = get_cross_reference_data(999)  # Non-existent file ID
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main() 