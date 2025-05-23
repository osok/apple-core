"""
Analyzer blueprint for Mach-O file analysis routes.
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, abort
from core import db
from core.models.macho_file import MachoFile
from core.models.header import Header
from core.models.segment import Segment
from core.models.section import Section
from core.services.analyzer_service import (
    get_file_data, get_header_data, get_segment_data, get_section_data,
    extract_symbol_tables, get_symbol_table_data, identify_cross_references,
    get_cross_reference_data
)
from core.services.editor_service import edit_field, get_edit_history
from core.services.visualization_service import (
    generate_symbol_distribution_data, generate_cross_reference_network
)

# Create blueprint
analyzer_bp = Blueprint('analyzer', __name__)

@analyzer_bp.route('/files/<int:file_id>', methods=['GET'])
def overview(file_id):
    """Show overview of a Mach-O file."""
    file_data = get_file_data(file_id)
    if not file_data:
        abort(404)
    return render_template('analyzer/overview.html', file_data=file_data)

@analyzer_bp.route('/files/<int:file_id>/header', methods=['GET'])
def header(file_id):
    """Show detailed header information for a Mach-O file."""
    header_data = get_header_data(file_id)
    if not header_data:
        abort(404)
    return render_template('analyzer/header.html', header_data=header_data)

@analyzer_bp.route('/files/<int:file_id>/segments', methods=['GET'])
def segments(file_id):
    """Show segments information for a Mach-O file."""
    segment_data = get_segment_data(file_id)
    if not segment_data:
        abort(404)
    return render_template('analyzer/segments.html', segment_data=segment_data)

@analyzer_bp.route('/files/<int:file_id>/segments/<int:segment_id>/sections', methods=['GET'])
def sections(file_id, segment_id):
    """Show sections information for a specific segment in a Mach-O file."""
    section_data = get_section_data(segment_id)
    if not section_data:
        abort(404)
    return render_template('analyzer/sections.html', section_data=section_data, file_id=file_id)

@analyzer_bp.route('/files/<int:file_id>/edit', methods=['GET', 'POST'])
def edit(file_id):
    """Handle editing of a Mach-O file."""
    file = MachoFile.query.get_or_404(file_id)
    
    if request.method == 'POST':
        target_type = request.form.get('target_type')
        target_id = request.form.get('target_id')
        new_value = request.form.get('new_value')
        
        result = edit_field(file_id, target_type, target_id, new_value)
        
        if result:
            flash('Edit applied successfully')
        else:
            flash('Edit failed')
        
        return redirect(url_for('analyzer.edit', file_id=file_id))
    
    # GET request - show edit history
    edit_history = get_edit_history(file_id)
    return render_template('analyzer/edit.html', file=file, edit_history=edit_history)

@analyzer_bp.route('/api/files/<int:file_id>/hex', methods=['GET'])
def get_hex_data(file_id):
    """API endpoint to get hex data for a specific offset and length."""
    file = MachoFile.query.get_or_404(file_id)
    
    offset = request.args.get('offset', default=0, type=int)
    length = request.args.get('length', default=256, type=int)
    
    try:
        with open(file.filepath, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
        
        # Convert binary data to hex representation
        hex_data = ' '.join(f'{b:02x}' for b in data)
        
        # Create basic interpretation for headers, segments, etc.
        # This is a simplified version - real implementation would be more complex
        interpretation = []
        
        return jsonify({
            'hex': hex_data,
            'interpretation': interpretation,
            'offset': offset,
            'length': len(data)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analyzer_bp.route('/files/<int:file_id>/notes', methods=['POST'])
def add_notes(file_id):
    """Handle adding notes to a file."""
    file = MachoFile.query.get_or_404(file_id)
    
    if request.method == 'POST':
        notes = request.form.get('notes')
        file.user_notes = notes
        db.session.commit()
        flash('Notes updated successfully')
    
    return redirect(url_for('analyzer.overview', file_id=file_id))

@analyzer_bp.route('/files/<int:file_id>/symbols', methods=['GET'])
def symbols(file_id):
    """Show symbol table information for a Mach-O file."""
    # Check if we need to extract symbol tables first
    if request.args.get('extract') == 'true':
        try:
            symtab, dysymtab = extract_symbol_tables(file_id)
            if symtab and dysymtab:
                flash('Symbol tables extracted successfully')
            elif symtab:
                flash('Symbol table extracted, no dynamic symbol table found')
            else:
                flash('No symbol tables found in the file')
        except Exception as e:
            flash(f'Error extracting symbol tables: {str(e)}')
    
    # Get symbol data
    symbol_data = get_symbol_table_data(file_id)
    if not symbol_data:
        abort(404)
    
    return render_template('analyzer/symbols.html', symbol_data=symbol_data)

@analyzer_bp.route('/api/files/<int:file_id>/symbol_distribution', methods=['GET'])
def get_symbol_distribution(file_id):
    """API endpoint to get symbol distribution data for visualization."""
    file = MachoFile.query.get_or_404(file_id)
    
    try:
        # Get symbol distribution data from visualization service
        distribution_data = generate_symbol_distribution_data(file_id)
        return jsonify(distribution_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analyzer_bp.route('/files/<int:file_id>/xrefs', methods=['GET'])
def xrefs(file_id):
    """Show cross-reference information for a Mach-O file."""
    # Check if we need to identify cross-references first
    if request.args.get('analyze') == 'true':
        try:
            xref_count = identify_cross_references(file_id)
            flash(f'Identified {xref_count} cross-references')
        except Exception as e:
            flash(f'Error identifying cross-references: {str(e)}')
    
    # Get cross-reference data
    xref_data = get_cross_reference_data(file_id)
    if not xref_data:
        abort(404)
    
    return render_template('analyzer/xrefs.html', xref_data=xref_data)

@analyzer_bp.route('/api/files/<int:file_id>/xref_network', methods=['GET'])
def get_xref_network(file_id):
    """API endpoint to get cross-reference network data for visualization."""
    file = MachoFile.query.get_or_404(file_id)
    
    try:
        # Get cross-reference network data from visualization service
        network_data = generate_cross_reference_network(file_id)
        return jsonify(network_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 