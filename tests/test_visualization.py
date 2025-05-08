"""
Tests for the visualization service functionality.
"""

import unittest
import json
from unittest.mock import patch
from core.services.visualization_service import (
    generate_section_size_data,
    generate_symbol_distribution_data,
    generate_cross_reference_network,
    generate_memory_map_data,
    generate_visualization_json
)
from core.models.macho_file import MachoFile
from core.models.segment import Segment
from core.models.section import Section
from core.models.symbol import Symbol
from core.models.cross_reference import CrossReference
from app import create_app
from core import db

class TestVisualizationService(unittest.TestCase):
    """Test cases for visualization service functionality."""
    
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
        
        # Create test segments and sections
        self.segments = [
            Segment(
                file_id=self.file_id,
                segname="__TEXT",
                vmaddr=0x100000000,
                vmsize=0x1000,
                fileoff=0,
                filesize=0x1000,
                maxprot=7,
                initprot=5,
                nsects=2,
                flags=0
            ),
            Segment(
                file_id=self.file_id,
                segname="__DATA",
                vmaddr=0x100001000,
                vmsize=0x1000,
                fileoff=0x1000,
                filesize=0x1000,
                maxprot=7,
                initprot=3,
                nsects=1,
                flags=0
            )
        ]
        
        for segment in self.segments:
            db.session.add(segment)
        db.session.commit()
        
        # Create test sections
        self.sections = [
            Section(
                segment_id=self.segments[0].id,
                sectname="__text",
                segname="__TEXT",
                addr=0x100000100,
                size=0x500,
                offset=0x100,
                align=4,
                flags=0x80000400
            ),
            Section(
                segment_id=self.segments[0].id,
                sectname="__stubs",
                segname="__TEXT",
                addr=0x100000600,
                size=0x200,
                offset=0x600,
                align=4,
                flags=0x80000408
            ),
            Section(
                segment_id=self.segments[1].id,
                sectname="__data",
                segname="__DATA",
                addr=0x100001000,
                size=0x800,
                offset=0x1000,
                align=3,
                flags=0
            )
        ]
        
        for section in self.sections:
            db.session.add(section)
        db.session.commit()
        
        # Create test symbols
        self.symbols = [
            Symbol(
                file_id=self.file_id,
                name="_main",
                type=0x0F,
                sect=1,
                desc=0,
                value=0x100000100,
                is_external=True,
                is_debug=False,
                is_local=False,
                is_defined=True
            ),
            Symbol(
                file_id=self.file_id,
                name="_helper",
                type=0x0F,
                sect=1,
                desc=0,
                value=0x100000200,
                is_external=False,
                is_debug=False,
                is_local=True,
                is_defined=True
            ),
            Symbol(
                file_id=self.file_id,
                name="_printf",
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
                type=0x0F,
                sect=1,
                desc=0,
                value=0x100000300,
                is_external=False,
                is_debug=True,
                is_local=True,
                is_defined=True
            )
        ]
        
        for symbol in self.symbols:
            db.session.add(symbol)
        db.session.commit()
        
        # Now that we have IDs, create test cross-references
        self.xrefs = [
            CrossReference(
                file_id=self.file_id,
                source_type='section',
                source_id=self.sections[0].id,  # Make sure we have a valid section ID
                target_type='symbol',
                target_id=self.symbols[0].id,   # Make sure we have a valid symbol ID
                offset=0,
                reference_type='contains'
            ),
            CrossReference(
                file_id=self.file_id,
                source_type='symbol',
                source_id=self.symbols[0].id,   # Make sure we have a valid symbol ID
                target_type='symbol',
                target_id=self.symbols[1].id,   # Make sure we have a valid symbol ID
                reference_type='calls'
            )
        ]
        
        for xref in self.xrefs:
            db.session.add(xref)
        db.session.commit()
        
    def tearDown(self):
        """Clean up after tests."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    def test_generate_section_size_data(self):
        """Test generating section size visualization data."""
        data = generate_section_size_data(self.file_id)
        
        # Verify data structure
        self.assertEqual(data['name'], 'Sections')
        self.assertEqual(len(data['children']), 2)  # Two segments
        
        # Verify segment data
        text_segment = next((s for s in data['children'] if s['name'] == '__TEXT'), None)
        self.assertIsNotNone(text_segment)
        self.assertEqual(len(text_segment['children']), 2)  # Two sections
        
        # Verify section data
        text_section = next((s for s in text_segment['children'] if s['name'] == '__text'), None)
        self.assertIsNotNone(text_section)
        self.assertEqual(text_section['value'], 0x500)
    
    def test_generate_symbol_distribution_data(self):
        """Test generating symbol distribution visualization data."""
        data = generate_symbol_distribution_data(self.file_id)
        
        # Verify data structure
        self.assertEqual(len(data), 4)  # Four symbol types
        
        # Verify symbol counts
        symbol_counts = {item['name']: item['value'] for item in data}
        self.assertEqual(symbol_counts['External'], 1)
        self.assertEqual(symbol_counts['Local'], 1)
        self.assertEqual(symbol_counts['Undefined'], 1)
        self.assertEqual(symbol_counts['Debug'], 1)
    
    def test_generate_cross_reference_network(self):
        """Test generating cross-reference network visualization data."""
        data = generate_cross_reference_network(self.file_id)
        
        # Verify data structure
        self.assertIn('nodes', data)
        self.assertIn('links', data)
        
        # Verify node count (1 section + 2 symbols involved in xrefs)
        self.assertEqual(len(data['nodes']), 3)
        
        # Verify link count
        self.assertEqual(len(data['links']), 2)
        
        # Verify node types
        node_types = [node['type'] for node in data['nodes']]
        self.assertIn('section', node_types)
        self.assertIn('symbol', node_types)
        
        # Verify link types
        link_types = [link['type'] for link in data['links']]
        self.assertIn('contains', link_types)
        self.assertIn('calls', link_types)
    
    def test_generate_memory_map_data(self):
        """Test generating memory map visualization data."""
        data = generate_memory_map_data(self.file_id)
        
        # Verify data structure
        self.assertEqual(len(data), 5)  # 2 segments + 3 sections
        
        # Verify segment data
        segments = [item for item in data if item['type'] == 'segment']
        self.assertEqual(len(segments), 2)
        
        # Verify section data
        sections = [item for item in data if item['type'] == 'section']
        self.assertEqual(len(sections), 3)
        
        # Verify addresses
        for item in data:
            if item['name'] == '__TEXT':
                self.assertEqual(item['start'], 0x100000000)
                self.assertEqual(item['end'], 0x100001000)
            elif item['name'] == '__text':
                self.assertEqual(item['start'], 0x100000100)
                self.assertEqual(item['end'], 0x100000600)
                self.assertEqual(item['parent'], '__TEXT')
    
    def test_generate_visualization_json(self):
        """Test generating complete visualization JSON."""
        json_data = generate_visualization_json(self.file_id)
        
        # Verify it's valid JSON
        data = json.loads(json_data)
        
        # Verify all visualization types are included
        self.assertIn('section_sizes', data)
        self.assertIn('symbol_distribution', data)
        self.assertIn('cross_references', data)
        self.assertIn('memory_map', data)

if __name__ == '__main__':
    unittest.main() 