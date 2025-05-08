"""
Service module for editing Mach-O files.
"""

import os
import shutil
from datetime import datetime
from core import db
from core.models.macho_file import MachoFile
from core.models.header import Header
from core.models.load_command import LoadCommand
from core.models.segment import Segment
from core.models.section import Section
from core.models.edit_history import EditHistory

def edit_field(file_id, target_type, target_id, new_value):
    """
    Edit a field in a Mach-O file using the command pattern.
    
    Args:
        file_id (int): The ID of the MachoFile record
        target_type (str): Type of target to edit ('header', 'segment', 'section')
        target_id (int): ID of the target record
        new_value: New value to set
        
    Returns:
        bool: True if edit successful, False otherwise
    """
    # Check if the file exists
    macho_file = MachoFile.query.get(file_id)
    if not macho_file:
        return False
    
    # Create edit command
    command = EditCommand(file_id, target_type, target_id, new_value)
    
    # Execute the command
    return command.execute()

def get_edit_history(file_id):
    """
    Get edit history for a file.
    
    Args:
        file_id (int): The ID of the MachoFile record
        
    Returns:
        list: List of EditHistory records
    """
    return EditHistory.query.filter_by(file_id=file_id).order_by(EditHistory.edit_timestamp.desc()).all()

class EditCommand:
    """
    Command pattern implementation for editing Mach-O files.
    """
    def __init__(self, file_id, target_type, target_id, new_value):
        self.file_id = file_id
        self.target_type = target_type
        self.target_id = int(target_id)
        self.new_value = new_value
        self.old_value = None
        self.history_id = None
    
    def execute(self):
        """Execute the edit operation."""
        # Get the file
        file = db.session.query(MachoFile).get(self.file_id)
        if not file:
            return False
        
        # Validate that the target exists
        target = self._get_target()
        if not target:
            return False
        
        # Read the current value
        self.old_value = self._read_current_value(target)
        
        # Create backup of the file
        backup_path = self._create_backup(file.filepath)
        if not backup_path:
            return False
        
        # Record in history
        history = EditHistory(
            file_id=self.file_id,
            edit_type='modify',
            target_type=self.target_type,
            target_id=self.target_id,
            before_value=self.old_value,
            after_value=self.new_value,
            status='pending'
        )
        db.session.add(history)
        db.session.commit()
        self.history_id = history.id
        
        # Apply the edit
        result = self._apply_edit(file.filepath, target)
        
        # Update history status
        history.status = 'applied' if result else 'failed'
        db.session.commit()
        
        return result
    
    def undo(self):
        """Undo the edit operation."""
        if not self.history_id:
            return False
        
        # Get the history record
        history = db.session.query(EditHistory).get(self.history_id)
        if not history or history.status != 'applied':
            return False
        
        # Get the file
        file = db.session.query(MachoFile).get(self.file_id)
        if not file:
            return False
        
        # Get the target
        target = self._get_target()
        if not target:
            return False
        
        # Revert to old value
        result = self._apply_value(file.filepath, target, self.old_value)
        
        # Update history status
        history.status = 'reverted' if result else 'failed'
        db.session.commit()
        
        return result
    
    def _get_target(self):
        """Get the target object based on type and ID."""
        if self.target_type == 'header':
            return Header.query.get(self.target_id)
        elif self.target_type == 'segment':
            return Segment.query.get(self.target_id)
        elif self.target_type == 'section':
            return Section.query.get(self.target_id)
        elif self.target_type == 'load_command':
            return LoadCommand.query.get(self.target_id)
        return None
    
    def _read_current_value(self, target):
        """Read the current value of the target field."""
        # This would actually read the binary file and extract the value
        # For now, we'll just use a placeholder
        return b'old_value'
    
    def _create_backup(self, file_path):
        """Create a backup of the file before editing."""
        backup_path = f"{file_path}.backup_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        try:
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception:
            return None
    
    def _apply_edit(self, file_path, target):
        """Apply the edit to the file."""
        # This would actually modify the binary file
        # For now, we'll just simulate success
        return True
    
    def _apply_value(self, file_path, target, value):
        """Apply a specific value to the file."""
        # This would actually modify the binary file with the given value
        # For now, we'll just simulate success
        return True 