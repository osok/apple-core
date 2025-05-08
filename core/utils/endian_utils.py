"""
Utility functions for handling endianness in Mach-O files.
"""

import struct
import enum
from typing import Union, Tuple, BinaryIO


class Endianness(enum.Enum):
    """Endianness enum for Mach-O files."""
    LITTLE = 0
    BIG = 1


def detect_endianness(magic: int) -> Endianness:
    """
    Detects the endianness of a Mach-O file based on its magic number.
    
    Args:
        magic: Magic number (uint32_t) from Mach-O header.
    
    Returns:
        Endianness enum value (LITTLE or BIG)
    """
    # Magic numbers for Mach-O files
    # Little endian: 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
    # Big endian: 0xCEFAEDFE (32-bit) or 0xCFFAEDFE (64-bit)
    if magic in (0xFEEDFACE, 0xFEEDFACF):
        return Endianness.LITTLE
    elif magic in (0xCEFAEDFE, 0xCFFAEDFE):
        return Endianness.BIG
    else:
        raise ValueError(f"Invalid Mach-O magic number: 0x{magic:08X}")


def is_64_bit(magic: int) -> bool:
    """
    Determines if a Mach-O file is 64-bit based on its magic number.
    
    Args:
        magic: Magic number (uint32_t) from Mach-O header.
    
    Returns:
        True if 64-bit, False if 32-bit
    """
    return magic in (0xFEEDFACF, 0xCFFAEDFE)


def read_uint32(file: BinaryIO, endianness: Endianness) -> int:
    """
    Reads a uint32_t from a binary file with correct endianness.
    
    Args:
        file: Binary file object
        endianness: Endianness of the file
    
    Returns:
        32-bit unsigned integer
    """
    fmt = '<I' if endianness == Endianness.LITTLE else '>I'
    return struct.unpack(fmt, file.read(4))[0]


def read_uint64(file: BinaryIO, endianness: Endianness) -> int:
    """
    Reads a uint64_t from a binary file with correct endianness.
    
    Args:
        file: Binary file object
        endianness: Endianness of the file
    
    Returns:
        64-bit unsigned integer
    """
    fmt = '<Q' if endianness == Endianness.LITTLE else '>Q'
    return struct.unpack(fmt, file.read(8))[0]


def read_format(file: BinaryIO, format_str: str, endianness: Endianness) -> Tuple:
    """
    Reads a formatted struct from a binary file with correct endianness.
    
    Args:
        file: Binary file object
        format_str: Format string (without endianness prefix)
        endianness: Endianness of the file
    
    Returns:
        Tuple of unpacked values
    """
    prefix = '<' if endianness == Endianness.LITTLE else '>'
    full_format = prefix + format_str
    size = struct.calcsize(full_format)
    data = file.read(size)
    return struct.unpack(full_format, data) 