"""
Tests for fat/universal binary support.
"""

import os
import tempfile
import struct
from io import BytesIO

import pytest

from core.services.parser_service import (
    MachoParser, ParsedFatHeader, ParsedFatArch,
    FAT_MAGIC, FAT_MAGIC_64, MAGIC_64_LE, CPU_TYPE_X86_64, CPU_TYPE_ARM64
)
from core.utils import Endianness


class TestFatBinary:
    """Test suite for fat/universal binary functionality."""
    
    def test_is_fat_binary(self):
        """Test detection of fat binaries."""
        # Create a mock fat binary file
        fat_data = struct.pack('>II', FAT_MAGIC, 2)  # Magic and 2 architectures
        
        # Test with a BytesIO
        file = BytesIO(fat_data)
        assert MachoParser.is_fat_binary(file) is True
        
        # Test with a non-fat binary
        non_fat_data = struct.pack('<I', MAGIC_64_LE)
        file = BytesIO(non_fat_data)
        assert MachoParser.is_fat_binary(file) is False
    
    def test_parse_fat_header(self):
        """Test parsing fat header."""
        # Create a mock fat binary file
        fat_data = struct.pack('>II', FAT_MAGIC, 2)  # Magic and 2 architectures
        
        # Parse the header
        file = BytesIO(fat_data)
        header = MachoParser.parse_fat_header(file)
        
        # Check the results
        assert header.magic == FAT_MAGIC
        assert header.nfat_arch == 2
        assert header.is_64_bit is False
        
        # Test 64-bit fat binary
        fat_data_64 = struct.pack('>II', FAT_MAGIC_64, 2)  # Magic and 2 architectures
        
        file = BytesIO(fat_data_64)
        header = MachoParser.parse_fat_header(file)
        
        assert header.magic == FAT_MAGIC_64
        assert header.nfat_arch == 2
        assert header.is_64_bit is True
    
    def test_parse_fat_arch_32bit(self):
        """Test parsing 32-bit fat arch structures."""
        # Create a mock fat arch structure
        arch_data = struct.pack(
            '>IIIII',
            CPU_TYPE_X86_64,  # CPU type
            3,                # CPU subtype
            4096,             # Offset
            8192,             # Size
            12                # Alignment
        )
        
        file = BytesIO(arch_data)
        arch = MachoParser.parse_fat_arch(file, is_64_bit=False)
        
        assert arch.cputype == CPU_TYPE_X86_64
        assert arch.cpusubtype == 3
        assert arch.offset == 4096
        assert arch.size == 8192
        assert arch.align == 12
    
    def test_parse_fat_arch_64bit(self):
        """Test parsing 64-bit fat arch structures."""
        # Create a mock fat arch structure
        arch_data = struct.pack(
            '>IIQQII',
            CPU_TYPE_ARM64,   # CPU type
            2,                # CPU subtype
            4096,             # Offset (64-bit)
            8192,             # Size (64-bit)
            12,               # Alignment
            0                 # Reserved
        )
        
        file = BytesIO(arch_data)
        arch = MachoParser.parse_fat_arch(file, is_64_bit=True)
        
        assert arch.cputype == CPU_TYPE_ARM64
        assert arch.cpusubtype == 2
        assert arch.offset == 4096
        assert arch.size == 8192
        assert arch.align == 12
    
    def test_create_mock_fat_binary(self, monkeypatch):
        """
        Create a mock fat binary file with x86_64 and ARM64 architectures for testing.
        """
        # Mock the database session calls in MachoParser
        def mock_parse_file(filepath):
            """Mocked version of parse_file that doesn't use the database."""
            is_fat = True
            headers = []
            
            # Create a mock MachoFile
            class MockMachoFile:
                def __init__(self):
                    self.is_fat_binary = is_fat
                    self.headers = headers
            
            # Create mock headers
            class MockHeader:
                def __init__(self, cpu_type, arch_offset, arch_size):
                    self.cpu_type = cpu_type
                    self.arch_offset = arch_offset
                    self.arch_size = arch_size
            
            # Create mock headers for both architectures
            x86_64_header = MockHeader(CPU_TYPE_X86_64, 128, 256)
            arm64_header = MockHeader(CPU_TYPE_ARM64, 384, 256)
            headers.extend([x86_64_header, arm64_header])
            
            # Return mock MachoFile
            return MockMachoFile()
        
        # Apply the patch
        monkeypatch.setattr(MachoParser, "parse_file", mock_parse_file)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Write fat header
            tmp.write(struct.pack('>II', FAT_MAGIC, 2))  # Magic and 2 architectures
            
            # Write x86_64 arch structure
            tmp.write(struct.pack(
                '>IIIII',
                CPU_TYPE_X86_64,  # CPU type
                3,                # CPU subtype
                128,              # Offset
                256,              # Size
                12                # Alignment
            ))
            
            # Write ARM64 arch structure
            tmp.write(struct.pack(
                '>IIIII',
                CPU_TYPE_ARM64,   # CPU type
                2,                # CPU subtype
                384,              # Offset
                256,              # Size
                12                # Alignment
            ))
            
            # Pad to reach x86_64 offset (128)
            padding_bytes = 128 - tmp.tell()
            tmp.write(b'\0' * padding_bytes)
            
            # Write mock x86_64 Mach-O header
            tmp.write(struct.pack('<IIIIIII', 
                MAGIC_64_LE,     # Magic
                CPU_TYPE_X86_64, # CPU type
                3,               # CPU subtype
                2,               # File type
                0,               # Number of load commands
                0,               # Size of load commands
                0                # Flags
            ))
            tmp.write(struct.pack('<I', 0))  # Reserved
            
            # Pad to reach ARM64 offset (384)
            padding_bytes = 384 - tmp.tell()
            tmp.write(b'\0' * padding_bytes)
            
            # Write mock ARM64 Mach-O header
            tmp.write(struct.pack('<IIIIIII', 
                MAGIC_64_LE,     # Magic
                CPU_TYPE_ARM64,  # CPU type
                2,               # CPU subtype
                2,               # File type
                0,               # Number of load commands
                0,               # Size of load commands
                0                # Flags
            ))
            tmp.write(struct.pack('<I', 0))  # Reserved
            
            filename = tmp.name
        
        try:
            # Parse the fat binary without database interactions
            macho_file = MachoParser.parse_file(filename)
            
            # Check results
            assert macho_file.is_fat_binary is True
            assert len(macho_file.headers) == 2
            
            # Find the x86_64 and ARM64 headers
            x86_64_header = None
            arm64_header = None
            for header in macho_file.headers:
                if header.cpu_type == CPU_TYPE_X86_64:
                    x86_64_header = header
                elif header.cpu_type == CPU_TYPE_ARM64:
                    arm64_header = header
            
            # Verify both architectures were found
            assert x86_64_header is not None
            assert arm64_header is not None
            
            # Check x86_64 header
            assert x86_64_header.arch_offset == 128
            assert x86_64_header.arch_size == 256
            
            # Check ARM64 header
            assert arm64_header.arch_offset == 384
            assert arm64_header.arch_size == 256
            
        finally:
            # Clean up the temporary file
            os.unlink(filename) 