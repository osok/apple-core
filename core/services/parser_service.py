"""
Parser services for Mach-O file analysis.
"""

import os
import struct
import pickle
from typing import BinaryIO, Dict, Any, Tuple, Optional, List
from pathlib import Path
from dataclasses import dataclass

from core import db
from core.utils import (
    Endianness, detect_endianness, is_64_bit,
    read_uint32, read_uint64, read_format
)
from core.models import MachoFile, Header, LoadCommand


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

# Load command types
LC_SEGMENT = 0x1             # 32-bit segment
LC_SYMTAB = 0x2              # Symbol table
LC_THREAD = 0x4              # Thread state
LC_UNIXTHREAD = 0x5          # Unix thread state
LC_DYSYMTAB = 0xB            # Dynamic symbol table
LC_LOAD_DYLIB = 0xC          # Load dynamic library
LC_ID_DYLIB = 0xD            # Dynamic library identification
LC_LOAD_DYLINKER = 0xE       # Load dynamic linker
LC_SEGMENT_64 = 0x19         # 64-bit segment
LC_UUID = 0x1B               # UUID
LC_CODE_SIGNATURE = 0x1D     # Code signature
LC_MAIN = 0x80000028         # Executable's main function
LC_FUNCTION_STARTS = 0x26    # Function start addresses
LC_DATA_IN_CODE = 0x29       # Data in code markers


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


@dataclass
class ParsedLoadCommand:
    """Data class for parsed Mach-O load command information."""
    cmd_type: int
    cmd_size: int
    cmd_offset: int
    cmd_data: bytes


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
            
            # Parse load commands
            load_commands = MachoParser.parse_load_commands(f, header_data)
            
            # Store load commands in the database
            for cmd in load_commands:
                load_cmd = LoadCommand(
                    header_id=header.id,
                    cmd_type=cmd.cmd_type,
                    cmd_size=cmd.cmd_size,
                    cmd_offset=cmd.cmd_offset,
                    cmd_data=cmd.cmd_data
                )
                db.session.add(load_cmd)
            
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
    def parse_load_commands(file: BinaryIO, header: ParsedHeader) -> List[ParsedLoadCommand]:
        """
        Parse all load commands from a Mach-O file.
        
        Args:
            file: Binary file object positioned after the header
            header: Parsed header information
            
        Returns:
            List[ParsedLoadCommand]: List of parsed load commands
        """
        load_commands = []
        endianness = header.endianness
        
        # Calculate the start position of load commands
        # For 32-bit Mach-O, this is after the 7 uint32 values (28 bytes)
        # For 64-bit Mach-O, this is after the 7 uint32 values + reserved field (32 bytes)
        start_offset = 28 if not header.is_64_bit else 32
        
        # Make sure we're at the correct position
        file.seek(start_offset)
        
        # Parse each load command
        for i in range(header.ncmds):
            # Remember command offset
            cmd_offset = file.tell()
            
            # Read command type and size
            cmd_type = read_uint32(file, endianness)
            cmd_size = read_uint32(file, endianness)
            
            # Go back to start of this command
            file.seek(cmd_offset)
            
            # Read the entire command data
            cmd_data = file.read(cmd_size)
            
            # Create a ParsedLoadCommand object
            load_cmd = ParsedLoadCommand(
                cmd_type=cmd_type,
                cmd_size=cmd_size,
                cmd_offset=cmd_offset,
                cmd_data=cmd_data
            )
            
            load_commands.append(load_cmd)
        
        return load_commands
    
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
    
    @staticmethod
    def get_load_command_name(cmd_type: int) -> str:
        """Convert load command type constant to human-readable name."""
        cmd_types = {
            LC_SEGMENT: "LC_SEGMENT",
            LC_SYMTAB: "LC_SYMTAB",
            LC_THREAD: "LC_THREAD",
            LC_UNIXTHREAD: "LC_UNIXTHREAD",
            LC_DYSYMTAB: "LC_DYSYMTAB",
            LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
            LC_ID_DYLIB: "LC_ID_DYLIB",
            LC_LOAD_DYLINKER: "LC_LOAD_DYLINKER",
            LC_SEGMENT_64: "LC_SEGMENT_64",
            LC_UUID: "LC_UUID",
            LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
            LC_MAIN: "LC_MAIN",
            LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS",
            LC_DATA_IN_CODE: "LC_DATA_IN_CODE",
        }
        return cmd_types.get(cmd_type, f"Unknown command (0x{cmd_type:x})") 