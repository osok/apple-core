"""
Tests for database schema validation.
"""

import pytest
from sqlalchemy.inspection import inspect
from core import create_app, db
from core.models.macho_file import MachoFile
from core.models.header import Header
from core.models.load_command import LoadCommand
from core.models.segment import Segment
from core.models.section import Section
from core.models.edit_history import EditHistory


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = create_app('testing')
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    yield app
    
    # Clean up
    with app.app_context():
        db.drop_all()


def test_macho_file_model(app):
    """Test MachoFile model and its relationships."""
    with app.app_context():
        # Check table name
        assert MachoFile.__tablename__ == 'files'
        
        # Check columns
        columns = [c.name for c in inspect(MachoFile).columns]
        assert 'id' in columns
        assert 'filename' in columns
        assert 'filepath' in columns
        assert 'file_size' in columns
        assert 'creation_date' in columns
        assert 'md5_hash' in columns
        assert 'user_notes' in columns
        
        # Check relationships
        relationships = inspect(MachoFile).relationships.keys()
        assert 'headers' in relationships
        assert 'segments' in relationships
        assert 'edit_history' in relationships


def test_header_model(app):
    """Test Header model and its relationships."""
    with app.app_context():
        # Check table name
        assert Header.__tablename__ == 'headers'
        
        # Check columns
        columns = [c.name for c in inspect(Header).columns]
        assert 'id' in columns
        assert 'file_id' in columns
        assert 'magic_number' in columns
        assert 'cpu_type' in columns
        assert 'cpu_subtype' in columns
        assert 'file_type' in columns
        assert 'ncmds' in columns
        assert 'sizeofcmds' in columns
        assert 'flags' in columns
        assert 'reserved' in columns
        
        # Check relationships
        relationships = inspect(Header).relationships.keys()
        assert 'file' in relationships
        assert 'load_commands' in relationships


def test_segment_model(app):
    """Test Segment model and its relationships."""
    with app.app_context():
        # Check table name
        assert Segment.__tablename__ == 'segments'
        
        # Check columns
        columns = [c.name for c in inspect(Segment).columns]
        assert 'id' in columns
        assert 'file_id' in columns
        assert 'segname' in columns
        assert 'vmaddr' in columns
        assert 'vmsize' in columns
        assert 'fileoff' in columns
        assert 'filesize' in columns
        assert 'maxprot' in columns
        assert 'initprot' in columns
        assert 'nsects' in columns
        assert 'flags' in columns
        
        # Check relationships
        relationships = inspect(Segment).relationships.keys()
        assert 'file' in relationships
        assert 'sections' in relationships


def test_section_model(app):
    """Test Section model and its relationships."""
    with app.app_context():
        # Check table name
        assert Section.__tablename__ == 'sections'
        
        # Check columns
        columns = [c.name for c in inspect(Section).columns]
        assert 'id' in columns
        assert 'segment_id' in columns
        assert 'sectname' in columns
        assert 'segname' in columns
        assert 'addr' in columns
        assert 'size' in columns
        assert 'offset' in columns
        assert 'align' in columns
        assert 'flags' in columns
        
        # Check relationships
        relationships = inspect(Section).relationships.keys()
        assert 'segment' in relationships


def test_load_command_model(app):
    """Test LoadCommand model and its relationships."""
    with app.app_context():
        # Check table name
        assert LoadCommand.__tablename__ == 'load_commands'
        
        # Check columns
        columns = [c.name for c in inspect(LoadCommand).columns]
        assert 'id' in columns
        assert 'header_id' in columns
        assert 'cmd_type' in columns
        assert 'cmd_size' in columns
        assert 'cmd_offset' in columns
        assert 'cmd_data' in columns
        
        # Check relationships
        relationships = inspect(LoadCommand).relationships.keys()
        assert 'header' in relationships


def test_edit_history_model(app):
    """Test EditHistory model and its relationships."""
    with app.app_context():
        # Check table name
        assert EditHistory.__tablename__ == 'edit_history'
        
        # Check columns
        columns = [c.name for c in inspect(EditHistory).columns]
        assert 'id' in columns
        assert 'file_id' in columns
        assert 'edit_timestamp' in columns
        assert 'edit_type' in columns
        assert 'target_type' in columns
        assert 'target_id' in columns
        assert 'before_value' in columns
        assert 'after_value' in columns
        assert 'status' in columns
        
        # Check relationships
        relationships = inspect(EditHistory).relationships.keys()
        assert 'file' in relationships


def test_relationships(app):
    """Test relationships between models."""
    with app.app_context():
        # Create test records
        macho_file = MachoFile(
            filename='test.bin',
            filepath='/tmp/test.bin',
            file_size=1024,
            md5_hash='deadbeef'
        )
        db.session.add(macho_file)
        db.session.flush()
        
        header = Header(
            file_id=macho_file.id,
            magic_number=0xfeedfacf,
            cpu_type=0x01000007,
            cpu_subtype=0x3,
            file_type=2,
            ncmds=10,
            sizeofcmds=1234,
            flags=0x85,
            reserved=0
        )
        db.session.add(header)
        db.session.flush()
        
        segment = Segment(
            file_id=macho_file.id,
            segname='__TEXT',
            vmaddr=0x100000000,
            vmsize=0x4000,
            fileoff=0,
            filesize=0x4000,
            maxprot=7,
            initprot=5,
            nsects=2,
            flags=0
        )
        db.session.add(segment)
        db.session.flush()
        
        section = Section(
            segment_id=segment.id,
            sectname='__text',
            segname='__TEXT',
            addr=0x100001000,
            size=0x1000,
            offset=0x1000,
            align=4,
            flags=0x80000400
        )
        db.session.add(section)
        
        load_command = LoadCommand(
            header_id=header.id,
            cmd_type=0x19,
            cmd_size=72,
            cmd_offset=0,
            cmd_data=b'\x19\x00\x00\x00\x48\x00\x00\x00'
        )
        db.session.add(load_command)
        
        edit_history = EditHistory(
            file_id=macho_file.id,
            edit_type='modify',
            target_type='header',
            target_id=header.id,
            before_value=b'old_value',
            after_value=b'new_value',
            status='applied'
        )
        db.session.add(edit_history)
        
        db.session.commit()
        
        # Test relationships
        # MachoFile -> Header
        assert len(macho_file.headers) == 1
        assert macho_file.headers[0].id == header.id
        
        # MachoFile -> Segment
        assert len(macho_file.segments) == 1
        assert macho_file.segments[0].id == segment.id
        
        # MachoFile -> EditHistory
        assert len(macho_file.edit_history) == 1
        assert macho_file.edit_history[0].id == edit_history.id
        
        # Header -> LoadCommand
        assert len(header.load_commands) == 1
        assert header.load_commands[0].id == load_command.id
        
        # Segment -> Section
        assert len(segment.sections) == 1
        assert segment.sections[0].id == section.id
        
        # Bidirectional relationships
        assert header.file.id == macho_file.id
        assert segment.file.id == macho_file.id
        assert section.segment.id == segment.id
        assert load_command.header.id == header.id
        assert edit_history.file.id == macho_file.id 