"""
Tests for the Mach-O header parser functionality.
"""

import os
import pytest
import tempfile
import struct
from io import BytesIO

from core.utils import Endianness
from core.utils.endian_utils import detect_endianness, is_64_bit, read_uint32, read_format
from core.services.parser_service import (
    MachoParser, ParsedHeader, ParsedLoadCommand,
    LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB, LC_LOAD_DYLIB
)


class TestEndianUtils:
    """Test suite for endianness utilities."""
    
    def test_detect_endianness(self):
        """Test detection of endianness from magic numbers."""
        # Little endian magic numbers
        assert detect_endianness(0xFEEDFACE) == Endianness.LITTLE  # 32-bit LE
        assert detect_endianness(0xFEEDFACF) == Endianness.LITTLE  # 64-bit LE
        
        # Big endian magic numbers
        assert detect_endianness(0xCEFAEDFE) == Endianness.BIG  # 32-bit BE
        assert detect_endianness(0xCFFAEDFE) == Endianness.BIG  # 64-bit BE
        
        # Invalid magic number
        with pytest.raises(ValueError):
            detect_endianness(0x12345678)
    
    def test_is_64_bit(self):
        """Test detection of 64-bit format from magic numbers."""
        # 32-bit magic numbers
        assert not is_64_bit(0xFEEDFACE)  # 32-bit LE
        assert not is_64_bit(0xCEFAEDFE)  # 32-bit BE
        
        # 64-bit magic numbers
        assert is_64_bit(0xFEEDFACF)  # 64-bit LE
        assert is_64_bit(0xCFFAEDFE)  # 64-bit BE
    
    def test_read_uint32(self):
        """Test reading uint32 with correct endianness."""
        # Little endian
        le_data = BytesIO(struct.pack('<I', 0x12345678))
        assert read_uint32(le_data, Endianness.LITTLE) == 0x12345678
        
        # Big endian
        be_data = BytesIO(struct.pack('>I', 0x12345678))
        assert read_uint32(be_data, Endianness.BIG) == 0x12345678
    
    def test_read_format(self):
        """Test reading formatted data with correct endianness."""
        # Test struct format: 2 uint32_t values
        test_format = "II"
        
        # Little endian
        le_data = BytesIO(struct.pack('<II', 0x11223344, 0x55667788))
        values = read_format(le_data, test_format, Endianness.LITTLE)
        assert values[0] == 0x11223344
        assert values[1] == 0x55667788
        
        # Big endian
        be_data = BytesIO(struct.pack('>II', 0x11223344, 0x55667788))
        values = read_format(be_data, test_format, Endianness.BIG)
        assert values[0] == 0x11223344
        assert values[1] == 0x55667788


class TestMachoParser:
    """Test suite for Mach-O parser functionality."""
    
    def test_parse_header_32bit_le(self):
        """Test parsing 32-bit little endian Mach-O header."""
        # Create a mock 32-bit LE header
        header_data = struct.pack('<IIIIIII',
                                 0xFEEDFACE,  # magic
                                 7,           # CPU_TYPE_X86
                                 3,           # CPU_SUBTYPE_X86
                                 2,           # MH_EXECUTE
                                 10,          # ncmds
                                 2048,        # sizeofcmds
                                 0x85)        # flags
        
        header_file = BytesIO(header_data)
        header = MachoParser.parse_header(header_file)
        
        assert header.magic == 0xFEEDFACE
        assert header.cpu_type == 7
        assert header.cpu_subtype == 3
        assert header.file_type == 2
        assert header.ncmds == 10
        assert header.sizeofcmds == 2048
        assert header.flags == 0x85
        assert header.reserved is None
        assert not header.is_64_bit
        assert header.endianness == Endianness.LITTLE
    
    def test_parse_header_64bit_le(self):
        """Test parsing 64-bit little endian Mach-O header."""
        # Create a mock 64-bit LE header
        header_data = struct.pack('<IIIIIII',
                                 0xFEEDFACF,      # magic
                                 0x01000007,      # CPU_TYPE_X86_64
                                 3,               # CPU_SUBTYPE_X86_64
                                 2,               # MH_EXECUTE
                                 15,              # ncmds
                                 4096,            # sizeofcmds
                                 0x85)            # flags
        
        # Add the reserved field for 64-bit
        header_data += struct.pack('<I', 0)
        
        header_file = BytesIO(header_data)
        header = MachoParser.parse_header(header_file)
        
        assert header.magic == 0xFEEDFACF
        assert header.cpu_type == 0x01000007
        assert header.cpu_subtype == 3
        assert header.file_type == 2
        assert header.ncmds == 15
        assert header.sizeofcmds == 4096
        assert header.flags == 0x85
        assert header.reserved == 0
        assert header.is_64_bit
        assert header.endianness == Endianness.LITTLE
    
    def test_parse_load_commands(self):
        """Test parsing load commands from a Mach-O file."""
        # Create a mock header with 2 load commands
        header_data = struct.pack('<IIIIIII',
                                 0xFEEDFACE,  # magic
                                 7,           # CPU_TYPE_X86
                                 3,           # CPU_SUBTYPE_X86
                                 2,           # MH_EXECUTE
                                 2,           # ncmds
                                 56,          # sizeofcmds (24 + 32)
                                 0x85)        # flags
        
        # Create load command 1: LC_SEGMENT (0x1)
        lc1_data = struct.pack('<II',
                              LC_SEGMENT,  # cmd type (0x1)
                              24)          # cmd size
        # Add some padding to reach cmd_size
        lc1_data += b'\0' * (24 - 8)
        
        # Create load command 2: LC_SYMTAB (0x2)
        lc2_data = struct.pack('<II',
                              LC_SYMTAB,   # cmd type (0x2)
                              32)          # cmd size
        # Add some padding to reach cmd_size
        lc2_data += b'\0' * (32 - 8)
        
        # Combine everything
        file_data = header_data + lc1_data + lc2_data
        file = BytesIO(file_data)
        
        # Create header object for testing
        header = ParsedHeader(
            magic=0xFEEDFACE,
            cpu_type=7,
            cpu_subtype=3,
            file_type=2,
            ncmds=2,
            sizeofcmds=56,
            flags=0x85,
            is_64_bit=False,
            endianness=Endianness.LITTLE
        )
        
        # Parse load commands
        load_commands = MachoParser.parse_load_commands(file, header)
        
        # Verify results
        assert len(load_commands) == 2
        
        # First command should be LC_SEGMENT
        assert load_commands[0].cmd_type == LC_SEGMENT
        assert load_commands[0].cmd_size == 24
        assert load_commands[0].cmd_offset == 28  # After 28-byte header
        
        # Second command should be LC_SYMTAB
        assert load_commands[1].cmd_type == LC_SYMTAB
        assert load_commands[1].cmd_size == 32
        assert load_commands[1].cmd_offset == 28 + 24  # After header + first command
    
    def test_parse_64bit_load_commands(self):
        """Test parsing load commands from a 64-bit Mach-O file."""
        # Create a mock 64-bit header with 2 load commands
        header_data = struct.pack('<IIIIIII',
                                 0xFEEDFACF,      # magic
                                 0x01000007,      # CPU_TYPE_X86_64
                                 3,               # CPU_SUBTYPE_X86_64
                                 2,               # MH_EXECUTE
                                 2,               # ncmds
                                 88,              # sizeofcmds (56 + 32)
                                 0x85)            # flags
        
        # Add the reserved field for 64-bit
        header_data += struct.pack('<I', 0)
        
        # Create load command 1: LC_SEGMENT_64 (0x19)
        lc1_data = struct.pack('<II',
                               LC_SEGMENT_64,  # cmd type (0x19)
                               56)             # cmd size
        # Add some padding to reach cmd_size
        lc1_data += b'\0' * (56 - 8)
        
        # Create load command 2: LC_LOAD_DYLIB (0xC)
        lc2_data = struct.pack('<II',
                               LC_LOAD_DYLIB,  # cmd type (0xC)
                               32)             # cmd size
        # Add some padding to reach cmd_size
        lc2_data += b'\0' * (32 - 8)
        
        # Combine everything
        file_data = header_data + lc1_data + lc2_data
        file = BytesIO(file_data)
        
        # Create header object for testing
        header = ParsedHeader(
            magic=0xFEEDFACF,
            cpu_type=0x01000007,
            cpu_subtype=3,
            file_type=2,
            ncmds=2,
            sizeofcmds=88,
            flags=0x85,
            reserved=0,
            is_64_bit=True,
            endianness=Endianness.LITTLE
        )
        
        # Parse load commands
        load_commands = MachoParser.parse_load_commands(file, header)
        
        # Verify results
        assert len(load_commands) == 2
        
        # First command should be LC_SEGMENT_64
        assert load_commands[0].cmd_type == LC_SEGMENT_64
        assert load_commands[0].cmd_size == 56
        assert load_commands[0].cmd_offset == 32  # After 32-byte header (includes reserved)
        
        # Second command should be LC_LOAD_DYLIB
        assert load_commands[1].cmd_type == LC_LOAD_DYLIB
        assert load_commands[1].cmd_size == 32
        assert load_commands[1].cmd_offset == 32 + 56  # After header + first command
    
    def test_cpu_type_name(self):
        """Test conversion of CPU type constants to human-readable names."""
        assert MachoParser.get_cpu_type_name(7) == "x86"
        assert MachoParser.get_cpu_type_name(0x01000007) == "x86_64"
        assert MachoParser.get_cpu_type_name(12) == "ARM"
        assert MachoParser.get_cpu_type_name(0x0100000C) == "ARM64"
        assert "Unknown" in MachoParser.get_cpu_type_name(999)
    
    def test_file_type_name(self):
        """Test conversion of file type constants to human-readable names."""
        assert MachoParser.get_file_type_name(1) == "Object file"
        assert MachoParser.get_file_type_name(2) == "Executable"
        assert MachoParser.get_file_type_name(6) == "Dynamic library"
        assert "Unknown" in MachoParser.get_file_type_name(999)
    
    def test_load_command_name(self):
        """Test conversion of load command constants to human-readable names."""
        assert MachoParser.get_load_command_name(LC_SEGMENT) == "LC_SEGMENT"
        assert MachoParser.get_load_command_name(LC_SEGMENT_64) == "LC_SEGMENT_64"
        assert MachoParser.get_load_command_name(LC_SYMTAB) == "LC_SYMTAB"
        assert MachoParser.get_load_command_name(LC_LOAD_DYLIB) == "LC_LOAD_DYLIB"
        assert "Unknown command" in MachoParser.get_load_command_name(0x9999) 