"""
Tests for the symbol table analysis functionality in the analyzer module.
"""

import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock
from core.services.analyzer_service import extract_symbol_tables, get_symbol_table_data
from core.models.macho_file import MachoFile
from core.models.symbol import Symbol, SymbolTable, DynamicSymbolTable
from app import create_app
from core import db

class TestSymbolTableAnalysis(unittest.TestCase):
    """Test cases for symbol table analysis functionality."""
    
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
        
    def tearDown(self):
        """Clean up after tests."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    @patch('core.services.analyzer_service.MachoParser')
    @patch('core.services.analyzer_service.MachO')
    @patch('builtins.open')
    def test_extract_symbol_tables(self, mock_open, mock_macho, mock_parser):
        """Test extracting symbol tables from a Mach-O file."""
        # Mock the MachO parsing
        mock_lc = MagicMock()
        mock_cmd_symtab = MagicMock()
        mock_cmd_symtab.symoff = 1000
        mock_cmd_symtab.nsyms = 50
        mock_cmd_symtab.stroff = 2000
        mock_cmd_symtab.strsize = 500
        
        mock_cmd_dysymtab = MagicMock()
        mock_cmd_dysymtab.ilocalsym = 0
        mock_cmd_dysymtab.nlocalsym = 20
        mock_cmd_dysymtab.iextdefsym = 20
        mock_cmd_dysymtab.nextdefsym = 20
        mock_cmd_dysymtab.iundefsym = 40
        mock_cmd_dysymtab.nundefsym = 10
        mock_cmd_dysymtab.indirectsymoff = 3000
        mock_cmd_dysymtab.nindirectsyms = 30
        
        # Set up the commands
        mock_lc.cmd = 0x2  # LC_SYMTAB
        mock_header = MagicMock()
        mock_header.header.magic = 0xfeedfacf  # 64-bit magic
        mock_header.commands = [
            (mock_lc, mock_cmd_symtab, None),
            (MagicMock(cmd=0xB), mock_cmd_dysymtab, None)  # LC_DYSYMTAB
        ]
        mock_macho.return_value.headers = [mock_header]
        
        # Mock symbol parsing
        mock_symbol = MagicMock()
        mock_symbol.name = "_test_symbol"
        mock_symbol.type = 0x1E
        mock_symbol.sect = 1
        mock_symbol.desc = 0
        mock_symbol.value = 0x1000
        mock_symbol.is_external = True
        mock_symbol.is_debug = False
        mock_symbol.is_local = False
        mock_symbol.is_defined = True
        
        mock_parser.parse_symbol_table.return_value = [mock_symbol]
        
        # Call the function
        symtab, dysymtab = extract_symbol_tables(self.file_id)
        
        # Verify the symbol table was extracted
        self.assertIsNotNone(symtab)
        self.assertEqual(symtab.file_id, self.file_id)
        self.assertEqual(symtab.symoff, 1000)
        self.assertEqual(symtab.nsyms, 50)
        self.assertEqual(symtab.stroff, 2000)
        self.assertEqual(symtab.strsize, 500)
        
        # Verify the dynamic symbol table was extracted
        self.assertIsNotNone(dysymtab)
        self.assertEqual(dysymtab.file_id, self.file_id)
        self.assertEqual(dysymtab.ilocalsym, 0)
        self.assertEqual(dysymtab.nlocalsym, 20)
        self.assertEqual(dysymtab.iextdefsym, 20)
        self.assertEqual(dysymtab.nextdefsym, 20)
        self.assertEqual(dysymtab.iundefsym, 40)
        self.assertEqual(dysymtab.nundefsym, 10)
        self.assertEqual(dysymtab.indirectsymoff, 3000)
        self.assertEqual(dysymtab.nindirectsyms, 30)
        
        # Verify symbol was created
        symbol = Symbol.query.filter_by(file_id=self.file_id).first()
        self.assertIsNotNone(symbol)
        self.assertEqual(symbol.name, "_test_symbol")
        self.assertEqual(symbol.type, 0x1E)
        self.assertEqual(symbol.sect, 1)
        self.assertEqual(symbol.value, 0x1000)
        self.assertTrue(symbol.is_external)
        self.assertFalse(symbol.is_debug)
        self.assertFalse(symbol.is_local)
        self.assertTrue(symbol.is_defined)
    
    def test_get_symbol_table_data(self):
        """Test retrieving symbol table data."""
        # Create test data
        symtab = SymbolTable(
            file_id=self.file_id,
            symoff=1000,
            nsyms=50,
            stroff=2000,
            strsize=500
        )
        
        dysymtab = DynamicSymbolTable(
            file_id=self.file_id,
            ilocalsym=0,
            nlocalsym=20,
            iextdefsym=20,
            nextdefsym=20,
            iundefsym=40,
            nundefsym=10,
            indirectsymoff=3000,
            nindirectsyms=30
        )
        
        # Create test symbols
        symbols = [
            Symbol(
                file_id=self.file_id,
                name="_local_symbol",
                type=0x0E,
                sect=1,
                desc=0,
                value=0x1000,
                is_external=False,
                is_debug=False,
                is_local=True,
                is_defined=True
            ),
            Symbol(
                file_id=self.file_id,
                name="_external_symbol",
                type=0x0F,
                sect=1,
                desc=0,
                value=0x2000,
                is_external=True,
                is_debug=False,
                is_local=False,
                is_defined=True
            ),
            Symbol(
                file_id=self.file_id,
                name="_undefined_symbol",
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
                name="_debug_symbol",
                type=0x2E,
                sect=1,
                desc=0,
                value=0x3000,
                is_external=False,
                is_debug=True,
                is_local=True,
                is_defined=True
            )
        ]
        
        db.session.add(symtab)
        db.session.add(dysymtab)
        for symbol in symbols:
            db.session.add(symbol)
        db.session.commit()
        
        # Get symbol table data
        data = get_symbol_table_data(self.file_id)
        
        # Verify data
        self.assertIsNotNone(data)
        self.assertEqual(data['file'].id, self.file_id)
        self.assertEqual(data['symtab'].id, symtab.id)
        self.assertEqual(data['dysymtab'].id, dysymtab.id)
        
        # Verify symbol counts
        self.assertEqual(data['symbols']['total'], 4)
        self.assertEqual(len(data['symbols']['local']), 2)  # local includes debug symbols
        self.assertEqual(len(data['symbols']['external']), 1)
        self.assertEqual(len(data['symbols']['undefined']), 1)
        self.assertEqual(len(data['symbols']['debug']), 1)
    
    @patch('core.services.analyzer_service.MachO')
    def test_extract_symbol_tables_no_file(self, mock_macho):
        """Test handling when file doesn't exist."""
        result = extract_symbol_tables(999)  # Non-existent file ID
        self.assertEqual(result, (None, None))
    
    @patch('core.services.analyzer_service.MachO')
    def test_extract_symbol_tables_no_headers(self, mock_macho):
        """Test handling when Mach-O has no headers."""
        mock_macho.return_value.headers = []
        result = extract_symbol_tables(self.file_id)
        self.assertEqual(result, (None, None))
    
    @patch('core.services.analyzer_service.MachO')
    def test_extract_symbol_tables_no_symbol_tables(self, mock_macho):
        """Test handling when Mach-O has no symbol tables."""
        mock_header = MagicMock()
        mock_header.commands = []  # No commands
        mock_macho.return_value.headers = [mock_header]
        
        symtab, dysymtab = extract_symbol_tables(self.file_id)
        
        self.assertIsNone(symtab)
        self.assertIsNone(dysymtab)

if __name__ == '__main__':
    unittest.main() 