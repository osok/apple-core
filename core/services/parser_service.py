"""
Parser services for Mach-O file analysis.
"""

import os
import struct
from typing import BinaryIO, Dict, Any, Tuple, Optional
from pathlib import Path
from dataclasses import dataclass

from core import db
from core.utils import (
    Endianness, detect_endianness, is_64_bit,
    read_uint32, read_uint64, read_format
)
from core.models import MachoFile, Header


# Magic numbers for Mach-O headers
MAGIC_32_LE = 0xFEEDFACE  # 32-bit little endian
MAGIC_64_LE = 0xFEEDFACF  # 64-bit little endian
MAGIC_32_BE = 0xCEFAEDFE  # 32-bit big endian
MAGIC_64_BE = 0xCFFAEDFE  # 64-bit big endian

# Constants for CPU types
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C

# File types
MH_OBJECT = 1        # Object file (.o)
MH_EXECUTE = 2       # Executable
MH_DYLIB = 6         # Dynamic library (.dylib)
MH_BUNDLE = 8        # Bundle
MH_DYLINKER = 10     # Dynamic linker
MH_DSYM = 10         # Debug symbols file


@dataclass
class ParsedHeader:
    """Data class for parsed Mach-O header information."""
    magic: int
    cpu_type: int
    cpu_subtype: int
    file_type: int
    ncmds: int
    sizeofcmds: int
    flags: int
    reserved: Optional[int] = None  # Only for 64-bit
    is_64_bit: bool = False
    endianness: Endianness = Endianness.LITTLE


class MachoParser:
    """Parser for Mach-O binary files."""
    
    @staticmethod
    def parse_file(filepath: str) -> MachoFile:
        """
        Parse a Mach-O file and store its information in the database.
        
        Args:
            filepath: Path to the Mach-O file
            
        Returns:
            MachoFile: Database model instance with file information
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
            
        file_size = path.stat().st_size
        file_hash = MachoParser._calculate_hash(filepath)
        
        with open(filepath, 'rb') as f:
            # Parse the Mach-O header
            header_data = MachoParser.parse_header(f)
            
            # Create a file record in the database
            macho_file = MachoFile(
                filename=path.name,
                filepath=str(path.absolute()),
                file_size=file_size,
                md5_hash=file_hash,
            )
            
            # Create a header record
            header = Header(
                file=macho_file,
                magic_number=header_data.magic,
                cpu_type=header_data.cpu_type,
                cpu_subtype=header_data.cpu_subtype,
                file_type=header_data.file_type,
                ncmds=header_data.ncmds,
                sizeofcmds=header_data.sizeofcmds,
                flags=header_data.flags,
                reserved=header_data.reserved,
            )
            
            db.session.add(macho_file)
            db.session.add(header)
            db.session.commit()
            
            return macho_file
    
    @staticmethod
    def parse_header(file: BinaryIO) -> ParsedHeader:
        """
        Parse the Mach-O header from a binary file.
        
        Args:
            file: Binary file object positioned at the start of the header
            
        Returns:
            ParsedHeader: Parsed header information
        """
        # Read magic number (first 4 bytes)
        magic_bytes = file.read(4)
        file.seek(-4, os.SEEK_CUR)  # Go back to start of file
        
        magic = struct.unpack('<I', magic_bytes)[0]
        endianness = detect_endianness(magic)
        is_64_bit_format = is_64_bit(magic)
        
        if is_64_bit_format:
            # 64-bit header format (mach_header_64)
            header_format = "IIIIIII"  # No reserved field yet
            header_data = read_format(file, header_format, endianness)
            magic, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = header_data
            
            # Read the reserved field (only in 64-bit headers)
            reserved = read_uint32(file, endianness)
            
            header = ParsedHeader(
                magic=magic,
                cpu_type=cpu_type,
                cpu_subtype=cpu_subtype,
                file_type=file_type,
                ncmds=ncmds,
                sizeofcmds=sizeofcmds,
                flags=flags,
                reserved=reserved,
                is_64_bit=True,
                endianness=endianness
            )
        else:
            # 32-bit header format (mach_header)
            header_format = "IIIIIII"
            header_data = read_format(file, header_format, endianness)
            magic, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = header_data
            
            header = ParsedHeader(
                magic=magic,
                cpu_type=cpu_type,
                cpu_subtype=cpu_subtype,
                file_type=file_type,
                ncmds=ncmds,
                sizeofcmds=sizeofcmds,
                flags=flags,
                is_64_bit=False,
                endianness=endianness
            )
        
        return header
    
    @staticmethod
    def _calculate_hash(filepath: str) -> str:
        """Calculate the MD5 hash of a file."""
        from core.utils import get_file_hash
        return get_file_hash(filepath)
    
    @staticmethod
    def get_cpu_type_name(cpu_type: int) -> str:
        """Convert CPU type constant to human-readable name."""
        cpu_types = {
            CPU_TYPE_X86: "x86",
            CPU_TYPE_X86_64: "x86_64",
            CPU_TYPE_ARM: "ARM",
            CPU_TYPE_ARM64: "ARM64",
        }
        return cpu_types.get(cpu_type, f"Unknown ({cpu_type})")
    
    @staticmethod
    def get_file_type_name(file_type: int) -> str:
        """Convert file type constant to human-readable name."""
        file_types = {
            MH_OBJECT: "Object file",
            MH_EXECUTE: "Executable",
            MH_DYLIB: "Dynamic library",
            MH_BUNDLE: "Bundle",
            MH_DYLINKER: "Dynamic linker",
            MH_DSYM: "Debug symbols",
        }
        return file_types.get(file_type, f"Unknown ({file_type})") 