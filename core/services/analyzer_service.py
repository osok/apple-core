"""
Service module for Mach-O file analysis and parsing.
"""

import struct
import os
import hashlib
import datetime
from macholib.MachO import MachO
from core import db
from core.models.macho_file import MachoFile
from core.models.header import Header
from core.models.load_command import LoadCommand
from core.models.segment import Segment
from core.models.section import Section
from core.models.symbol import Symbol, SymbolTable, DynamicSymbolTable
from core.models.cross_reference import CrossReference
from core.services.parser_service import MachoParser

def parse_and_store_macho_file(filepath):
    """
    Parse a Mach-O file and store its data using our custom parser.
    
    Args:
        filepath (str): Path to the Mach-O file
        
    Returns:
        MachoFile: Database model instance with file information
    """
    return MachoParser.parse_file(filepath)

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

def extract_symbol_tables(file_id):
    """
    Extract and store symbol table information for a Mach-O file.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        tuple: (SymbolTable, DynamicSymbolTable) if successful, (None, None) otherwise
    """
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return None, None
    
    try:
        # Parse Mach-O file using macholib
        macho = MachO(macho_file.filepath)
        
        # Process first header for symbol tables
        if not macho.headers:
            return None, None
            
        header = macho.headers[0]
        symtab_cmd = None
        dysymtab_cmd = None
        
        # Find symbol table and dynamic symbol table load commands
        for lc, cmd, _ in header.commands:
            if lc.cmd == 0x2:  # LC_SYMTAB
                symtab_cmd = cmd
            elif lc.cmd == 0xB:  # LC_DYSYMTAB
                dysymtab_cmd = cmd
        
        # Process symbol table if found
        symtab_record = None
        if symtab_cmd:
            symtab_record = SymbolTable(
                file_id=file_id,
                symoff=symtab_cmd.symoff,
                nsyms=symtab_cmd.nsyms,
                stroff=symtab_cmd.stroff,
                strsize=symtab_cmd.strsize
            )
            db.session.add(symtab_record)
            db.session.flush()  # Get ID for relationships
            
            # Parse symbols using our custom parser
            with open(macho_file.filepath, 'rb') as f:
                symbols = MachoParser.parse_symbol_table(f, symtab_cmd, header.header.magic)
                
                # Store symbols in database
                for sym in symbols:
                    symbol = Symbol(
                        file_id=file_id,
                        name=sym.name,
                        type=sym.type,
                        sect=sym.sect,
                        desc=sym.desc,
                        value=sym.value,
                        is_external=sym.is_external,
                        is_debug=sym.is_debug,
                        is_local=sym.is_local,
                        is_defined=sym.is_defined
                    )
                    db.session.add(symbol)
        
        # Process dynamic symbol table if found
        dysymtab_record = None
        if dysymtab_cmd:
            dysymtab_record = DynamicSymbolTable(
                file_id=file_id,
                ilocalsym=dysymtab_cmd.ilocalsym,
                nlocalsym=dysymtab_cmd.nlocalsym,
                iextdefsym=dysymtab_cmd.iextdefsym,
                nextdefsym=dysymtab_cmd.nextdefsym,
                iundefsym=dysymtab_cmd.iundefsym,
                nundefsym=dysymtab_cmd.nundefsym,
                indirectsymoff=getattr(dysymtab_cmd, 'indirectsymoff', None),
                nindirectsyms=getattr(dysymtab_cmd, 'nindirectsyms', None)
            )
            db.session.add(dysymtab_record)
        
        # Commit all changes to database
        db.session.commit()
        return symtab_record, dysymtab_record
        
    except Exception as e:
        # Roll back transaction on error
        db.session.rollback()
        raise e

def identify_cross_references(file_id):
    """
    Identify and store cross-references between symbols and sections.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        int: Number of cross-references identified
    """
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return 0
    
    try:
        # Get symbols, sections, and segments for this file
        symbols = Symbol.query.filter_by(file_id=file_id).all()
        segments = Segment.query.filter_by(file_id=file_id).all()
        
        # Collect all sections from all segments
        sections = []
        for segment in segments:
            sections.extend(Section.query.filter_by(segment_id=segment.id).all())
        
        # Create a map of addresses to symbols and sections
        addr_to_symbol = {sym.value: sym for sym in symbols if sym.is_defined}
        addr_to_section = {section.addr: section for section in sections}
        
        # Cross-reference count
        xref_count = 0
        
        # Find symbols in sections
        for symbol in symbols:
            if not symbol.is_defined:
                continue
                
            # Find containing section for this symbol
            for section in sections:
                if (section.addr <= symbol.value < section.addr + section.size):
                    # Create cross-reference from section to symbol
                    xref = CrossReference(
                        file_id=file_id,
                        source_type='section',
                        source_id=section.id,
                        target_type='symbol',
                        target_id=symbol.id,
                        offset=symbol.value - section.addr,
                        reference_type='contains'
                    )
                    db.session.add(xref)
                    xref_count += 1
                    break
        
        # Find symbol references to other symbols
        for symbol in symbols:
            if not symbol.is_defined or symbol.sect == 0:  # Skip undefined symbols
                continue
                
            # Find references to other symbols (simplified approach)
            # A more advanced implementation would analyze the binary code
            # Here we're just tracking potential data references based on addresses
            for target_sym in symbols:
                if symbol.id == target_sym.id:
                    continue
                    
                # If a symbol points to an address related to another symbol
                if symbol.value == target_sym.value:
                    xref = CrossReference(
                        file_id=file_id,
                        source_type='symbol',
                        source_id=symbol.id,
                        target_type='symbol',
                        target_id=target_sym.id,
                        reference_type='references'
                    )
                    db.session.add(xref)
                    xref_count += 1
        
        # Commit all changes to database
        db.session.commit()
        return xref_count
        
    except Exception as e:
        # Roll back transaction on error
        db.session.rollback()
        raise e

def get_symbol_table_data(file_id):
    """
    Get symbol table information for a Mach-O file.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Symbol table data
    """
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return None
    
    symtab = SymbolTable.query.filter_by(file_id=file_id).first()
    dysymtab = DynamicSymbolTable.query.filter_by(file_id=file_id).first()
    
    # Get symbols by category
    symbols = Symbol.query.filter_by(file_id=file_id).all()
    
    local_symbols = [s for s in symbols if s.is_local]
    external_symbols = [s for s in symbols if s.is_external and s.is_defined]
    undefined_symbols = [s for s in symbols if not s.is_defined]
    debug_symbols = [s for s in symbols if s.is_debug]
    
    return {
        'file': macho_file,
        'symtab': symtab,
        'dysymtab': dysymtab,
        'symbols': {
            'total': len(symbols),
            'local': local_symbols,
            'external': external_symbols,
            'undefined': undefined_symbols,
            'debug': debug_symbols
        }
    }

def get_cross_reference_data(file_id):
    """
    Get cross-reference information for a Mach-O file.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Cross-reference data
    """
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return None
    
    xrefs = CrossReference.query.filter_by(file_id=file_id).all()
    
    # Process cross-references for display
    xref_data = []
    for xref in xrefs:
        # Get source and target names
        source_name = "Unknown"
        target_name = "Unknown"
        
        if xref.source_type == 'symbol':
            sym = Symbol.query.get(xref.source_id)
            if sym:
                source_name = sym.name
        elif xref.source_type == 'section':
            section = Section.query.get(xref.source_id)
            if section:
                source_name = f"{section.segname},{section.sectname}"
                
        if xref.target_type == 'symbol':
            sym = Symbol.query.get(xref.target_id)
            if sym:
                target_name = sym.name
        elif xref.target_type == 'section':
            section = Section.query.get(xref.target_id)
            if section:
                target_name = f"{section.segname},{section.sectname}"
        
        xref_data.append({
            'id': xref.id,
            'source_type': xref.source_type,
            'source_id': xref.source_id,
            'source_name': source_name,
            'target_type': xref.target_type,
            'target_id': xref.target_id,
            'target_name': target_name,
            'offset': xref.offset,
            'reference_type': xref.reference_type
        })
    
    return {
        'file': macho_file,
        'xrefs': xref_data,
        'count': len(xref_data)
    }

def extract_file_metadata(filepath):
    """
    Extract and store detailed metadata for a Mach-O file.
    
    Args:
        filepath (str): Path to the Mach-O file
        
    Returns:
        MachoFile: Database model instance with metadata
    """
    # Get basic file information
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)
    
    # Calculate MD5 hash
    md5_hash = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5_hash.update(chunk)
    
    # Check if file already exists in database
    existing_file = MachoFile.query.filter_by(md5_hash=md5_hash.hexdigest()).first()
    if existing_file:
        # Update existing record with current filepath
        existing_file.filepath = filepath
        existing_file.filename = filename
        existing_file.file_size = file_size
        db.session.commit()
        return existing_file
    
    # Create new file record with extended metadata
    try:
        # Try to parse with macholib to get basic validation
        macho = MachO(filepath)
        
        # Determine file type (executable, library, object, etc.)
        file_type = "Unknown"
        if macho.headers:
            header = macho.headers[0].header
            if hasattr(header, 'filetype'):
                filetype_map = {
                    0x1: "MH_OBJECT",      # Object file
                    0x2: "MH_EXECUTE",     # Executable
                    0x3: "MH_FVMLIB",      # Fixed VM shared library
                    0x4: "MH_CORE",        # Core file
                    0x5: "MH_PRELOAD",     # Preloaded executable
                    0x6: "MH_DYLIB",       # Dynamic shared library
                    0x7: "MH_DYLINKER",    # Dynamic linker
                    0x8: "MH_BUNDLE",      # Bundle
                    0x9: "MH_DYLIB_STUB",  # Shared library stub
                    0xA: "MH_DSYM",        # Debug symbols
                    0xB: "MH_KEXT_BUNDLE", # Kernel extension
                }
                file_type = filetype_map.get(header.filetype, "Unknown")
        
        # Determine architecture
        architecture = "Unknown"
        if macho.headers:
            header = macho.headers[0].header
            if hasattr(header, 'cputype'):
                cpu_map = {
                    0x7: "Intel x86",
                    0x1000007: "Intel x86-64",
                    0xC: "ARM",
                    0x100000C: "ARM64",
                }
                architecture = cpu_map.get(header.cputype, "Unknown")
        
        # Create new MachoFile record with extended metadata
        macho_file = MachoFile(
            filename=filename,
            filepath=filepath,
            file_size=file_size,
            md5_hash=md5_hash.hexdigest(),
            file_type=file_type,
            architecture=architecture,
            creation_date=datetime.datetime.now()
        )
        
        db.session.add(macho_file)
        db.session.commit()
        return macho_file
        
    except Exception as e:
        db.session.rollback()
        raise e 