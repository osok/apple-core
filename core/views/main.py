"""
Main blueprint for general routes like index and file upload.
"""

import os
import hashlib
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.utils import secure_filename
from core import db
from core.models.macho_file import MachoFile
from core.services.analyzer_service import process_macho_file

# Create blueprint
main_bp = Blueprint('main', __name__)

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

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
    
    # Process file if it exists and has allowed extension
    if file and allowed_file(file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file
        file.save(file_path)
        
        # Calculate file size and MD5 hash
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        
        # Create file record in database
        macho_file = MachoFile(
            filename=filename,
            filepath=file_path,
            file_size=file_size,
            md5_hash=file_hash
        )
        db.session.add(macho_file)
        db.session.commit()
        
        # Process the file asynchronously
        try:
            process_macho_file(macho_file.id)
            flash(f'File {filename} uploaded and processed successfully')
        except Exception as e:
            flash(f'Error processing file: {str(e)}')
        
        return redirect(url_for('analyzer.overview', file_id=macho_file.id))
    
    flash('Invalid file type')
    return redirect(url_for('main.index')) 