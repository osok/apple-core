"""
Utility functions for file operations.
"""

import os
import hashlib
from werkzeug.utils import secure_filename
from flask import current_app

def allowed_file(filename):
    """
    Check if a file has an allowed extension.
    
    Args:
        filename (str): The filename to check
        
    Returns:
        bool: True if file has an allowed extension, False otherwise
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def get_file_hash(file_path, hash_type='md5'):
    """
    Calculate hash for a file.
    
    Args:
        file_path (str): Path to the file
        hash_type (str): Type of hash to calculate ('md5', 'sha1', 'sha256')
        
    Returns:
        str: Hexadecimal hash digest
    """
    hash_funcs = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }
    
    if hash_type not in hash_funcs:
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    hash_obj = hash_funcs[hash_type]()
    
    with open(file_path, 'rb') as f:
        # Read in chunks to handle large files
        for chunk in iter(lambda: f.read(4096), b''):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()

def save_uploaded_file(file, filename=None):
    """
    Save an uploaded file to the upload folder.
    
    Args:
        file: The file object from request.files
        filename (str, optional): Filename to use. If None, uses the original filename.
        
    Returns:
        str: Path to the saved file, or None on failure
    """
    if not file:
        return None
    
    # Secure the filename
    if filename is None:
        filename = secure_filename(file.filename)
    else:
        filename = secure_filename(filename)
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    
    # Ensure the upload directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    try:
        file.save(file_path)
        return file_path
    except Exception:
        return None 