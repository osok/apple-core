"""
Visualization service for Mach-O analysis data preparation.
"""

import json
from collections import defaultdict
from core.models.macho_file import MachoFile
from core.models.segment import Segment
from core.models.section import Section
from core.models.symbol import Symbol
from core.models.cross_reference import CrossReference

def generate_section_size_data(file_id):
    """
    Generate data for visualizing section sizes.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Data suitable for visualization libraries
    """
    # Get all segments for this file
    segments = Segment.query.filter_by(file_id=file_id).all()
    
    # Prepare data structure
    data = {
        'name': 'Sections',
        'children': []
    }
    
    # Group sections by segment
    for segment in segments:
        segment_data = {
            'name': segment.segname,
            'children': []
        }
        
        sections = Section.query.filter_by(segment_id=segment.id).all()
        
        for section in sections:
            section_data = {
                'name': section.sectname,
                'value': section.size
            }
            segment_data['children'].append(section_data)
        
        # Only add segments that have sections
        if segment_data['children']:
            data['children'].append(segment_data)
    
    return data

def generate_symbol_distribution_data(file_id):
    """
    Generate data for visualizing symbol distribution.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Data suitable for visualization libraries
    """
    # Get all symbols for this file
    symbols = Symbol.query.filter_by(file_id=file_id).all()
    
    # Count symbols by type
    symbol_types = defaultdict(int)
    
    for symbol in symbols:
        if symbol.is_debug:
            symbol_types['Debug'] += 1
        elif not symbol.is_defined:
            symbol_types['Undefined'] += 1
        elif symbol.is_external:
            symbol_types['External'] += 1
        else:
            symbol_types['Local'] += 1
    
    # Convert to list of objects for visualization
    data = [
        {'name': key, 'value': value}
        for key, value in symbol_types.items()
    ]
    
    return data

def generate_cross_reference_network(file_id):
    """
    Generate data for visualizing cross-references as a network graph.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Data suitable for network visualization libraries
    """
    xrefs = CrossReference.query.filter_by(file_id=file_id).all()
    
    # Collect unique nodes
    nodes = {}
    
    # First pass: gather all symbols and sections as nodes
    for xref in xrefs:
        # Source node
        if xref.source_type == 'symbol':
            sym = Symbol.query.get(xref.source_id)
            if sym and sym.id not in nodes:
                nodes[f"symbol-{sym.id}"] = {
                    'id': f"symbol-{sym.id}",
                    'name': sym.name,
                    'type': 'symbol',
                    'category': 'symbol'
                }
        elif xref.source_type == 'section':
            section = Section.query.get(xref.source_id)
            if section and section.id not in nodes:
                nodes[f"section-{section.id}"] = {
                    'id': f"section-{section.id}",
                    'name': f"{section.segname},{section.sectname}",
                    'type': 'section',
                    'category': 'section'
                }
        
        # Target node
        if xref.target_type == 'symbol':
            sym = Symbol.query.get(xref.target_id)
            if sym and sym.id not in nodes:
                nodes[f"symbol-{sym.id}"] = {
                    'id': f"symbol-{sym.id}",
                    'name': sym.name,
                    'type': 'symbol',
                    'category': 'symbol'
                }
        elif xref.target_type == 'section':
            section = Section.query.get(xref.target_id)
            if section and section.id not in nodes:
                nodes[f"section-{section.id}"] = {
                    'id': f"section-{section.id}",
                    'name': f"{section.segname},{section.sectname}",
                    'type': 'section',
                    'category': 'section'
                }
    
    # Create links from cross-references
    links = []
    
    for xref in xrefs:
        source_id = f"{xref.source_type}-{xref.source_id}"
        target_id = f"{xref.target_type}-{xref.target_id}"
        
        if source_id in nodes and target_id in nodes:
            links.append({
                'source': source_id,
                'target': target_id,
                'type': xref.reference_type
            })
    
    return {
        'nodes': list(nodes.values()),
        'links': links
    }

def generate_memory_map_data(file_id):
    """
    Generate data for visualizing memory layout.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        dict: Data suitable for visualization libraries
    """
    # Get all segments for this file
    segments = Segment.query.filter_by(file_id=file_id).order_by(Segment.vmaddr).all()
    
    data = []
    
    # Add segments to memory map
    for segment in segments:
        data.append({
            'name': segment.segname,
            'start': segment.vmaddr,
            'end': segment.vmaddr + segment.vmsize,
            'size': segment.vmsize,
            'type': 'segment'
        })
        
        # Add sections within each segment
        sections = Section.query.filter_by(segment_id=segment.id).order_by(Section.addr).all()
        for section in sections:
            data.append({
                'name': section.sectname,
                'start': section.addr,
                'end': section.addr + section.size,
                'size': section.size,
                'parent': segment.segname,
                'type': 'section'
            })
    
    return data

def generate_visualization_json(file_id):
    """
    Generate all visualization data for a file as JSON.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        str: JSON string containing all visualization data
    """
    visualization_data = {
        'section_sizes': generate_section_size_data(file_id),
        'symbol_distribution': generate_symbol_distribution_data(file_id),
        'cross_references': generate_cross_reference_network(file_id),
        'memory_map': generate_memory_map_data(file_id)
    }
    
    return json.dumps(visualization_data) 