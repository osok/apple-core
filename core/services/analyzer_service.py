"""
Service module for Mach-O file analysis and parsing.
"""

import struct
from macholib.MachO import MachO
from core import db
from core.models.macho_file import MachoFile
from core.models.header import Header
from core.models.load_command import LoadCommand
from core.models.segment import Segment
from core.models.section import Section

def process_macho_file(file_id):
    """
    Process a Mach-O file to extract all relevant information.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Get file record from database
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return False
    
    try:
        # Parse Mach-O file using macholib
        macho = MachO(macho_file.filepath)
        
        # Process each header (for fat binaries, there can be multiple)
        for index, header in enumerate(macho.headers):
            # Extract header data
            mach_header = header.header
            
            # Create Header record
            header_record = Header(
                file_id=file_id,
                magic_number=mach_header.magic,
                cpu_type=mach_header.cputype,
                cpu_subtype=mach_header.cpusubtype,
                file_type=mach_header.filetype,
                ncmds=mach_header.ncmds,
                sizeofcmds=mach_header.sizeofcmds,
                flags=mach_header.flags,
                reserved=getattr(mach_header, 'reserved', None)
            )
            db.session.add(header_record)
            db.session.flush()  # Get ID for relationships
            
            # Process load commands
            for cmd_index, (lc, cmd, data) in enumerate(header.commands):
                # Create LoadCommand record
                load_cmd = LoadCommand(
                    header_id=header_record.id,
                    cmd_type=lc.cmd,
                    cmd_size=lc.cmdsize,
                    cmd_offset=cmd_index,  # Store index for reference
                    cmd_data=data  # Store raw command data
                )
                db.session.add(load_cmd)
                
                # Process segment commands specifically
                if lc.cmd in (0x1, 0x19):  # LC_SEGMENT or LC_SEGMENT_64
                    segname = cmd.segname.decode('utf-8').rstrip('\0')
                    
                    # Create Segment record
                    segment = Segment(
                        file_id=file_id,
                        segname=segname,
                        vmaddr=cmd.vmaddr,
                        vmsize=cmd.vmsize,
                        fileoff=cmd.fileoff,
                        filesize=cmd.filesize,
                        maxprot=cmd.maxprot,
                        initprot=cmd.initprot,
                        nsects=cmd.nsects,
                        flags=cmd.flags
                    )
                    db.session.add(segment)
                    db.session.flush()  # Get ID for relationships
                    
                    # Process sections within the segment
                    for sect in cmd.sections:
                        sectname = sect.sectname.decode('utf-8').rstrip('\0')
                        segname = sect.segname.decode('utf-8').rstrip('\0')
                        
                        # Create Section record
                        section = Section(
                            segment_id=segment.id,
                            sectname=sectname,
                            segname=segname,
                            addr=sect.addr,
                            size=sect.size,
                            offset=sect.offset,
                            align=sect.align,
                            flags=sect.flags
                        )
                        db.session.add(section)
                
        # Commit all changes to database
        db.session.commit()
        return True
        
    except Exception as e:
        # Roll back transaction on error
        db.session.rollback()
        raise e

def get_file_data(file_id):
    """
    Get overview data for a Mach-O file.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: File data including headers and segments summary
    """
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return None
    
    headers = Header.query.filter_by(file_id=file_id).all()
    segments = Segment.query.filter_by(file_id=file_id).all()
    
    # Count sections per segment
    segment_data = []
    for segment in segments:
        section_count = Section.query.filter_by(segment_id=segment.id).count()
        segment_data.append({
            'id': segment.id,
            'name': segment.segname,
            'address': segment.vmaddr,
            'size': segment.vmsize,
            'protection': segment.protection_string,
            'section_count': section_count
        })
    
    return {
        'file': macho_file,
        'headers': headers,
        'segments': segment_data,
        'header_count': len(headers),
        'segment_count': len(segments)
    }

def get_header_data(file_id):
    """
    Get detailed header information for a Mach-O file.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Header data including load commands
    """
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return None
    
    headers = Header.query.filter_by(file_id=file_id).all()
    
    header_data = []
    for header in headers:
        load_commands = LoadCommand.query.filter_by(header_id=header.id).all()
        
        # Format load commands for display
        cmd_data = []
        for lc in load_commands:
            cmd_data.append({
                'id': lc.id,
                'type': lc.cmd_type,
                'size': lc.cmd_size,
                'offset': lc.cmd_offset
            })
        
        header_data.append({
            'header': header,
            'load_commands': cmd_data,
            'command_count': len(load_commands)
        })
    
    return {
        'file': macho_file,
        'headers': header_data
    }

def get_segment_data(file_id):
    """
    Get segment information for a Mach-O file.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Segment data including protection information
    """
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return None
    
    segments = Segment.query.filter_by(file_id=file_id).all()
    
    segment_data = []
    for segment in segments:
        section_count = Section.query.filter_by(segment_id=segment.id).count()
        segment_data.append({
            'segment': segment,
            'section_count': section_count
        })
    
    return {
        'file': macho_file,
        'segments': segment_data
    }

def get_section_data(segment_id):
    """
    Get section information for a specific segment.
    
    Args:
        segment_id (int): The ID of the Segment record
        
    Returns:
        dict: Section data including types and flags
    """
    segment = Segment.query.get(segment_id)
    if not segment:
        return None
    
    sections = Section.query.filter_by(segment_id=segment_id).all()
    
    return {
        'segment': segment,
        'sections': sections
    } 