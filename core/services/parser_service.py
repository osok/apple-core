"""
Parser services for Mach-O file analysis.
"""

import os
import struct
import pickle
from typing import BinaryIO, Dict, Any, Tuple, Optional, List, NamedTuple
from io import BytesIO
from pathlib import Path
from dataclasses import dataclass

from core import db
from core.utils import (
    Endianness, detect_endianness, is_64_bit,
    read_uint32, read_uint64, read_format
)
from core.models import MachoFile, Header, LoadCommand, Segment, Section


# Magic numbers for Mach-O headers
MAGIC_32_LE = 0xFEEDFACE  # 32-bit little endian
MAGIC_64_LE = 0xFEEDFACF  # 64-bit little endian
MAGIC_32_BE = 0xCEFAEDFE  # 32-bit big endian
MAGIC_64_BE = 0xCFFAEDFE  # 64-bit big endian

# Fat/Universal binary magic numbers
FAT_MAGIC = 0xCAFEBABE    # Big-endian fat binary
FAT_MAGIC_64 = 0xCAFEBABF  # Big-endian 64-bit fat binary

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

# Symbol type masks
N_STAB = 0xe0  # Symbolic debugging entry - If any of these bits are set, the entry is a symbolic debugging entry
N_PEXT = 0x10  # Private external symbol
N_TYPE = 0x0e  # Type field
N_EXT  = 0x01  # External symbol

# Symbol type values (N_TYPE)
N_UNDF = 0x0   # Undefined symbol
N_ABS  = 0x2   # Absolute symbol
N_SECT = 0xe   # Symbol is defined in the section number given in n_sect
N_PBUD = 0xc   # Prebound undefined symbol
N_INDR = 0xa   # Indirect symbol

# Symbol reference flags
REFERENCE_FLAG_UNDEFINED_NON_LAZY = 0x0
REFERENCE_FLAG_UNDEFINED_LAZY     = 0x1
REFERENCE_FLAG_DEFINED            = 0x2
REFERENCE_FLAG_PRIVATE_DEFINED    = 0x3
REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY = 0x4
REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY = 0x5

# Additional symbol flags
REFERENCED_DYNAMICALLY = 0x10
N_DESC_DISCARDED = 0x20
N_NO_DEAD_STRIP = 0x20
N_WEAK_REF = 0x40
N_WEAK_DEF = 0x80


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
class ParsedFatHeader:
    """Data class for parsed Fat/Universal binary header."""
    magic: int
    nfat_arch: int
    is_64_bit: bool = False


@dataclass
class ParsedFatArch:
    """Data class for parsed Fat/Universal binary architecture slice."""
    cputype: int
    cpusubtype: int
    offset: int
    size: int
    align: int


@dataclass
class ParsedLoadCommand:
    """Data class for parsed Mach-O load command information."""
    cmd_type: int
    cmd_size: int
    cmd_offset: int
    cmd_data: bytes


@dataclass
class ParsedSegment:
    """Data class for parsed Mach-O segment information."""
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    nsects: int
    flags: int
    cmd_offset: int
    is_64_bit: bool = False
    sections: List = None


@dataclass
class ParsedSection:
    """Data class for parsed Mach-O section information."""
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int
    align: int
    flags: int


@dataclass
class ParsedSymbol:
    """
    Represents a parsed symbol from a Mach-O file's symbol table.
    """
    name: str
    type: int
    sect: int
    desc: int
    value: int
    is_external: bool
    is_debug: bool
    is_local: bool
    is_defined: bool


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
            # Check if this is a fat/universal binary
            if MachoParser.is_fat_binary(f):
                # Parse the fat header
                fat_header = MachoParser.parse_fat_header(f)
                
                # Create a file record in the database
                macho_file = MachoFile(
                    filename=path.name,
                    filepath=str(path.absolute()),
                    file_size=file_size,
                    md5_hash=file_hash,
                    is_fat_binary=True
                )
                
                db.session.add(macho_file)
                db.session.commit()
                
                # Parse each architecture slice
                for i in range(fat_header.nfat_arch):
                    fat_arch = MachoParser.parse_fat_arch(f, fat_header.is_64_bit)
                    
                    # Save the original position
                    original_pos = f.tell()
                    
                    # Move to the Mach-O object for this architecture
                    f.seek(fat_arch.offset)
                    
                    # Parse the Mach-O header for this architecture
                    header_data = MachoParser.parse_header(f)
                    
                    # Create a header record for this architecture
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
                        arch_offset=fat_arch.offset,
                        arch_size=fat_arch.size
                    )
                    
                    db.session.add(header)
                    db.session.commit()
                    
                    # Parse load commands for this architecture
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
                    
                    # Parse segments and sections for this architecture
                    segments = MachoParser.parse_segments_and_sections(f, header_data, load_commands)
                    
                    # Store segments and sections in the database
                    for segment in segments:
                        # Create segment record
                        seg_record = Segment(
                            file_id=macho_file.id,
                            segname=segment.segname,
                            vmaddr=segment.vmaddr,
                            vmsize=segment.vmsize,
                            fileoff=segment.fileoff,
                            filesize=segment.filesize,
                            maxprot=segment.maxprot,
                            initprot=segment.initprot,
                            nsects=segment.nsects,
                            flags=segment.flags
                        )
                        db.session.add(seg_record)
                        db.session.flush()  # Get ID for relationships
                        
                        # Create section records if they exist
                        if segment.sections:
                            for section in segment.sections:
                                sect_record = Section(
                                    segment_id=seg_record.id,
                                    sectname=section.sectname,
                                    segname=section.segname,
                                    addr=section.addr,
                                    size=section.size,
                                    offset=section.offset,
                                    align=section.align,
                                    flags=section.flags
                                )
                                db.session.add(sect_record)
                    
                    db.session.commit()
                    
                    # Restore the original position to read the next fat arch
                    f.seek(original_pos)
                
                return macho_file
            else:
                # Regular Mach-O file processing
                # Parse the Mach-O header
                header_data = MachoParser.parse_header(f)
                
                # Create a file record in the database
                macho_file = MachoFile(
                    filename=path.name,
                    filepath=str(path.absolute()),
                    file_size=file_size,
                    md5_hash=file_hash,
                    is_fat_binary=False
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
                    reserved=header_data.reserved
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
                
                # Parse segments and sections
                segments = MachoParser.parse_segments_and_sections(f, header_data, load_commands)
                
                # Store segments and sections in the database
                for segment in segments:
                    # Create segment record
                    seg_record = Segment(
                        file_id=macho_file.id,
                        segname=segment.segname,
                        vmaddr=segment.vmaddr,
                        vmsize=segment.vmsize,
                        fileoff=segment.fileoff,
                        filesize=segment.filesize,
                        maxprot=segment.maxprot,
                        initprot=segment.initprot,
                        nsects=segment.nsects,
                        flags=segment.flags
                    )
                    db.session.add(seg_record)
                    db.session.flush()  # Get ID for relationships
                    
                    # Create section records if they exist
                    if segment.sections:
                        for section in segment.sections:
                            sect_record = Section(
                                segment_id=seg_record.id,
                                sectname=section.sectname,
                                segname=section.segname,
                                addr=section.addr,
                                size=section.size,
                                offset=section.offset,
                                align=section.align,
                                flags=section.flags
                            )
                            db.session.add(sect_record)
                
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
    
    @staticmethod
    def parse_segments_and_sections(file: BinaryIO, header: ParsedHeader, load_commands: List[ParsedLoadCommand]) -> List[ParsedSegment]:
        """
        Parse segments and sections from load commands.
        
        Args:
            file: Binary file object
            header: Parsed header information
            load_commands: List of parsed load commands
            
        Returns:
            List[ParsedSegment]: List of parsed segments with their sections
        """
        segments = []
        endianness = header.endianness
        is_64_bit = header.is_64_bit
        
        # Look for segment commands (LC_SEGMENT or LC_SEGMENT_64)
        for cmd in load_commands:
            if cmd.cmd_type == LC_SEGMENT or cmd.cmd_type == LC_SEGMENT_64:
                # Process segment based on 32-bit or 64-bit format
                segment = MachoParser._parse_segment_command(cmd, endianness, is_64_bit)
                
                # If the segment has sections, parse them
                if segment.nsects > 0:
                    segment.sections = MachoParser._parse_sections(cmd, segment, endianness, is_64_bit)
                else:
                    segment.sections = []
                
                segments.append(segment)
        
        return segments
    
    @staticmethod
    def _parse_segment_command(cmd: ParsedLoadCommand, endianness: Endianness, is_64_bit: bool) -> ParsedSegment:
        """
        Parse a segment command (LC_SEGMENT or LC_SEGMENT_64).
        
        Args:
            cmd: Load command data
            endianness: File endianness
            is_64_bit: Whether this is a 64-bit segment
            
        Returns:
            ParsedSegment: Parsed segment information
        """
        # Create a BytesIO object from the command data
        cmd_io = BytesIO(cmd.cmd_data)
        
        # Skip the command type and size (already read)
        cmd_io.seek(8)
        
        # Read segment name (16 bytes for both 32-bit and 64-bit)
        segname_bytes = cmd_io.read(16)
        segname = segname_bytes.decode('utf-8').rstrip('\0')
        
        # Read the rest of the segment command based on format
        if is_64_bit:
            # 64-bit segment
            vmaddr = read_uint64(cmd_io, endianness)
            vmsize = read_uint64(cmd_io, endianness)
            fileoff = read_uint64(cmd_io, endianness)
            filesize = read_uint64(cmd_io, endianness)
        else:
            # 32-bit segment
            vmaddr = read_uint32(cmd_io, endianness)
            vmsize = read_uint32(cmd_io, endianness)
            fileoff = read_uint32(cmd_io, endianness)
            filesize = read_uint32(cmd_io, endianness)
        
        # Read protection and section count (same for 32-bit and 64-bit)
        maxprot = read_uint32(cmd_io, endianness)
        initprot = read_uint32(cmd_io, endianness)
        nsects = read_uint32(cmd_io, endianness)
        flags = read_uint32(cmd_io, endianness)
        
        return ParsedSegment(
            segname=segname,
            vmaddr=vmaddr,
            vmsize=vmsize,
            fileoff=fileoff,
            filesize=filesize,
            maxprot=maxprot,
            initprot=initprot,
            nsects=nsects,
            flags=flags,
            cmd_offset=cmd.cmd_offset,
            is_64_bit=is_64_bit,
            sections=None
        )
    
    @staticmethod
    def _parse_sections(cmd: ParsedLoadCommand, segment: ParsedSegment, endianness: Endianness, is_64_bit: bool) -> List[ParsedSection]:
        """
        Parse sections from a segment command.
        
        Args:
            cmd: Load command data
            segment: Parent segment information
            endianness: File endianness
            is_64_bit: Whether this is a 64-bit segment
            
        Returns:
            List[ParsedSection]: List of parsed sections
        """
        sections = []
        cmd_io = BytesIO(cmd.cmd_data)
        
        # Calculate offset to first section
        # For 32-bit: command header (8) + segname (16) + 4 uint32s (vmaddr, vmsize, fileoff, filesize) + 4 more uint32s = 56
        # For 64-bit: command header (8) + segname (16) + 4 uint64s (vmaddr, vmsize, fileoff, filesize) + 4 uint32s = 72
        section_offset = 56 if not is_64_bit else 72
        cmd_io.seek(section_offset)
        
        # Section size
        # For 32-bit: 2 names (32) + 7 uint32s = 60
        # For 64-bit: 2 names (32) + 2 uint64s + 5 uint32s = 68
        section_size = 60 if not is_64_bit else 68
        
        # Parse each section
        for i in range(segment.nsects):
            # Read section name and segment name (same for 32-bit and 64-bit)
            sectname_bytes = cmd_io.read(16)
            segname_bytes = cmd_io.read(16)
            sectname = sectname_bytes.decode('utf-8').rstrip('\0')
            segname = segname_bytes.decode('utf-8').rstrip('\0')
            
            # Read address and size
            if is_64_bit:
                # 64-bit section
                addr = read_uint64(cmd_io, endianness)
                size = read_uint64(cmd_io, endianness)
            else:
                # 32-bit section
                addr = read_uint32(cmd_io, endianness)
                size = read_uint32(cmd_io, endianness)
            
            # Read remaining fields (same for 32-bit and 64-bit)
            offset = read_uint32(cmd_io, endianness)
            align = read_uint32(cmd_io, endianness)
            reloff = read_uint32(cmd_io, endianness)  # Not stored in our model but must read
            nreloc = read_uint32(cmd_io, endianness)  # Not stored in our model but must read
            flags = read_uint32(cmd_io, endianness)
            
            # Skip the reserved fields (different size based on architecture)
            if is_64_bit:
                cmd_io.read(12)  # reserved1, reserved2, reserved3 (3 uint32s)
            else:
                cmd_io.read(8)   # reserved1, reserved2 (2 uint32s)
            
            # Create section object
            section = ParsedSection(
                sectname=sectname,
                segname=segname,
                addr=addr,
                size=size,
                offset=offset,
                align=align,
                flags=flags
            )
            
            sections.append(section)
        
        return sections
    
    @staticmethod
    def is_fat_binary(file: BinaryIO) -> bool:
        """
        Check if a file is a fat/universal binary.
        
        Args:
            file: Binary file object positioned at the start
            
        Returns:
            bool: True if the file is a fat binary, False otherwise
        """
        # Save the current position
        current_pos = file.tell()
        
        # Read magic number (first 4 bytes)
        magic_bytes = file.read(4)
        file.seek(current_pos)  # Restore the position
        
        # Check if it's a fat binary magic number
        if len(magic_bytes) == 4:
            magic = struct.unpack('>I', magic_bytes)[0]  # Fat headers are always big endian
            return magic in (FAT_MAGIC, FAT_MAGIC_64)
        
        return False
    
    @staticmethod
    def parse_fat_header(file: BinaryIO) -> ParsedFatHeader:
        """
        Parse a fat binary header.
        
        Args:
            file: Binary file object positioned at the start
            
        Returns:
            ParsedFatHeader: Parsed fat header information
        """
        # Fat headers are always big endian
        magic = struct.unpack('>I', file.read(4))[0]
        nfat_arch = struct.unpack('>I', file.read(4))[0]
        
        is_64_bit = (magic == FAT_MAGIC_64)
        
        return ParsedFatHeader(
            magic=magic,
            nfat_arch=nfat_arch,
            is_64_bit=is_64_bit
        )
    
    @staticmethod
    def parse_fat_arch(file: BinaryIO, is_64_bit: bool) -> ParsedFatArch:
        """
        Parse a fat architecture structure.
        
        Args:
            file: Binary file object positioned at the start of the arch structure
            is_64_bit: Whether this is a 64-bit fat binary
            
        Returns:
            ParsedFatArch: Parsed fat architecture information
        """
        # Fat arch structures are always big endian
        cputype = struct.unpack('>I', file.read(4))[0]
        cpusubtype = struct.unpack('>I', file.read(4))[0]
        
        if is_64_bit:
            # 64-bit fat arch structure has 64-bit offset and size
            offset = struct.unpack('>Q', file.read(8))[0]
            size = struct.unpack('>Q', file.read(8))[0]
        else:
            # 32-bit fat arch structure has 32-bit offset and size
            offset = struct.unpack('>I', file.read(4))[0]
            size = struct.unpack('>I', file.read(4))[0]
        
        align = struct.unpack('>I', file.read(4))[0]
        
        # Skip reserved field in 64-bit fat arch
        if is_64_bit:
            file.read(4)  # Skip reserved field
        
        return ParsedFatArch(
            cputype=cputype,
            cpusubtype=cpusubtype,
            offset=offset,
            size=size,
            align=align
        )
    
    @staticmethod
    def parse_symbol_table(file: BinaryIO, symtab_cmd, magic: int) -> List[ParsedSymbol]:
        """
        Parse the symbol table of a Mach-O file.
        
        Args:
            file: Binary file object
            symtab_cmd: Symbol table command
            magic: Magic number from the Mach-O header
            
        Returns:
            List[ParsedSymbol]: List of parsed symbols
        """
        symbols = []
        is_64bit = is_64_bit(magic)
        endianness = detect_endianness(magic)
        symbol_size = 16 if is_64bit else 12  # Size of nlist_64 or nlist structure
        
        # Read string table
        file.seek(symtab_cmd.stroff)
        string_table = file.read(symtab_cmd.strsize)
        
        # Seek to symbol table
        file.seek(symtab_cmd.symoff)
        
        for i in range(symtab_cmd.nsyms):
            if is_64bit:
                # Read 64-bit symbol entry
                n_strx = read_uint32(file, endianness)
                n_type = int.from_bytes(file.read(1), byteorder='little')
                n_sect = int.from_bytes(file.read(1), byteorder='little')
                n_desc = struct.unpack('<h', file.read(2))[0]  # 16-bit signed
                n_value = read_uint64(file, endianness)
            else:
                # Read 32-bit symbol entry
                n_strx = read_uint32(file, endianness)
                n_type = int.from_bytes(file.read(1), byteorder='little')
                n_sect = int.from_bytes(file.read(1), byteorder='little')
                n_desc = struct.unpack('<h', file.read(2))[0]  # 16-bit signed
                n_value = read_uint32(file, endianness)
            
            # Get symbol name from string table
            try:
                # Start at the string offset and read until null terminator
                name_start = n_strx
                if name_start < 0 or name_start >= len(string_table):
                    name = f"INVALID_STRING_OFFSET_{n_strx}"
                else:
                    name_end = string_table.find(b'\0', name_start)
                    if name_end < 0:
                        name = string_table[name_start:].decode('utf-8', errors='replace')
                    else:
                        name = string_table[name_start:name_end].decode('utf-8', errors='replace')
            except Exception:
                name = f"INVALID_STRING_{n_strx}"
            
            # Determine symbol characteristics
            is_external = bool(n_type & N_EXT)
            is_debug = bool(n_type & N_STAB)
            n_type_masked = n_type & N_TYPE
            
            is_defined = n_type_masked == N_SECT or n_type_masked == N_ABS
            is_local = not is_external and not is_debug
            
            # Create ParsedSymbol object
            symbol = ParsedSymbol(
                name=name,
                type=n_type,
                sect=n_sect,
                desc=n_desc,
                value=n_value,
                is_external=is_external,
                is_debug=is_debug,
                is_local=is_local,
                is_defined=is_defined
            )
            
            symbols.append(symbol)
        
        return symbols
    
    @staticmethod
    def get_symbol_type_name(type_value: int) -> str:
        """Convert symbol type value to human-readable name."""
        n_type = type_value & N_TYPE
        
        if n_type == N_UNDF:
            return "Undefined"
        elif n_type == N_ABS:
            return "Absolute"
        elif n_type == N_SECT:
            return "Defined in Section"
        elif n_type == N_PBUD:
            return "Prebound Undefined"
        elif n_type == N_INDR:
            return "Indirect"
        else:
            return f"Unknown ({n_type})" 