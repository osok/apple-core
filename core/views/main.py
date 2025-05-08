"""
Main blueprint for general routes like index and file upload.
"""

import os
import hashlib
import subprocess
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.utils import secure_filename
from core import db
from core.models.macho_file import MachoFile
from core.services.analyzer_service import process_macho_file, extract_file_metadata

# Create blueprint
main_bp = Blueprint('main', __name__)

def allowed_file(filename):
    """
    Check if the file is allowed.
    First checks by extension, then by file type if no extension.
    """
    # First try to check by extension
    if '.' in filename:
        return filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']
    
    # If no extension, check the actual file content using the 'file' command
    # This requires the uploaded file to be saved temporarily first
    return True  # Allow all files without extension for now, we'll check content later

@main_bp.route('/', methods=['GET'])
def index():
    """Render the index page with file upload form."""
    files = MachoFile.query.order_by(MachoFile.creation_date.desc()).all()
    return render_template('index.html', files=files)

@main_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and initial processing."""
    # Check if file part exists in request
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    
    # Check if user selected a file
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    # Initial check for allowed file by extension
    has_valid_extension = '.' in file.filename and \
        file.filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']
    
    # Process file if it exists and passes initial extension check or has no extension
    if file and (has_valid_extension or '.' not in file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file
        file.save(file_path)
        
        # For files without extension, verify it's a Mach-O file
        if not has_valid_extension:
            try:
                # Use the 'file' command to detect file type
                result = subprocess.run(['file', file_path], capture_output=True, text=True)
                output = result.stdout.lower()
                
                # Check if the output contains "mach-o"
                if 'mach-o' not in output:
                    # Not a Mach-O file, delete it and return error
                    os.remove(file_path)
                    flash('Invalid file type: File is not a Mach-O binary')
                    return redirect(url_for('main.index'))
            except Exception as e:
                # Error running file command, delete file and return error
                os.remove(file_path)
                flash(f'Error checking file type: {str(e)}')
                return redirect(url_for('main.index'))
        
        try:
            # Extract and store file metadata
            macho_file = extract_file_metadata(file_path)
            
            # Process the file
            process_macho_file(macho_file.id)
            flash(f'File {filename} uploaded and processed successfully')
            
            return redirect(url_for('analyzer.overview', file_id=macho_file.id))
        except Exception as e:
            # Try to delete the file if it exists
            if os.path.exists(file_path):
                os.remove(file_path)
            flash(f'Error processing file: {str(e)}')
            return redirect(url_for('main.index'))
    
    flash('Invalid file type')
    return redirect(url_for('main.index')) 