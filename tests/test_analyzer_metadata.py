"""
Tests for the metadata extraction functionality in the analyzer module.
"""

import os
import unittest
import tempfile
import hashlib
from unittest.mock import patch, MagicMock
from core.services.analyzer_service import extract_file_metadata
from core.models.macho_file import MachoFile
from app import create_app
from core import db

class TestMetadataExtraction(unittest.TestCase):
    """Test cases for metadata extraction functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
        # Create a temporary test file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b'\xfe\xed\xfa\xce\x00\x00\x00\x0c\x00\x00\x00\x01')  # Mock Mach-O header
        self.temp_file.close()
        
        # Calculate MD5 hash for the test file
        md5_hash = hashlib.md5()
        with open(self.temp_file.name, 'rb') as f:
            md5_hash.update(f.read())
        self.test_md5 = md5_hash.hexdigest()
        
    def tearDown(self):
        """Clean up after tests."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        os.unlink(self.temp_file.name)
    
    @patch('core.services.analyzer_service.MachO')
    def test_extract_new_file_metadata(self, mock_macho):
        """Test extracting metadata from a new file."""
        # Mock MachO object and header
        mock_header = MagicMock()
        mock_header.header.filetype = 0x2  # MH_EXECUTE
        mock_header.header.cputype = 0x1000007  # Intel x86-64
        
        mock_macho.return_value.headers = [mock_header]
        
        # Call the function
        macho_file = extract_file_metadata(self.temp_file.name)
        
        # Verify the file was created in the database
        self.assertIsNotNone(macho_file)
        self.assertEqual(macho_file.md5_hash, self.test_md5)
        self.assertEqual(macho_file.filepath, self.temp_file.name)
        self.assertEqual(macho_file.file_type, "MH_EXECUTE")
        self.assertEqual(macho_file.architecture, "Intel x86-64")
        
        # Verify the file was stored in the database
        db_file = MachoFile.query.filter_by(md5_hash=self.test_md5).first()
        self.assertIsNotNone(db_file)
        self.assertEqual(db_file.id, macho_file.id)
    
    @patch('core.services.analyzer_service.MachO')
    def test_extract_existing_file_metadata(self, mock_macho):
        """Test updating metadata for an existing file."""
        # Create an existing file record
        existing_file = MachoFile(
            filename="old_name.bin",
            filepath="/old/path/old_name.bin",
            file_size=12,
            md5_hash=self.test_md5,
            file_type="MH_EXECUTE",
            architecture="Intel x86-64"
        )
        db.session.add(existing_file)
        db.session.commit()
        original_id = existing_file.id
        
        # Mock MachO object
        mock_macho.return_value.headers = []
        
        # Call the function with a new path
        updated_file = extract_file_metadata(self.temp_file.name)
        
        # Verify the existing file was updated
        self.assertEqual(updated_file.id, original_id)
        self.assertEqual(updated_file.md5_hash, self.test_md5)
        self.assertEqual(updated_file.filepath, self.temp_file.name)
        self.assertEqual(updated_file.filename, os.path.basename(self.temp_file.name))
        
    @patch('core.services.analyzer_service.MachO')
    def test_extract_file_metadata_error(self, mock_macho):
        """Test handling errors during metadata extraction."""
        # Make MachO throw an exception
        mock_macho.side_effect = Exception("Test exception")
        
        # Verify that the exception is propagated
        with self.assertRaises(Exception):
            extract_file_metadata(self.temp_file.name)
        
        # Verify no file was added to the database
        db_file = MachoFile.query.filter_by(md5_hash=self.test_md5).first()
        self.assertIsNone(db_file)

if __name__ == '__main__':
    unittest.main() 