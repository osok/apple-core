"""Add symbol and cross-reference tables

Revision ID: a48ef93bcdef
Revises: add_fat_binary_support
Create Date: 2023-09-04 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a48ef93bcdef'
down_revision = 'add_fat_binary_support'
branch_labels = None
depends_on = None


def upgrade():
    # Create the symbols table
    op.create_table('symbols',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('file_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('type', sa.Integer(), nullable=False),
        sa.Column('sect', sa.Integer(), nullable=False),
        sa.Column('desc', sa.Integer(), nullable=False),
        sa.Column('value', sa.BigInteger(), nullable=False),
        sa.Column('is_external', sa.Boolean(), default=False),
        sa.Column('is_debug', sa.Boolean(), default=False),
        sa.Column('is_local', sa.Boolean(), default=False),
        sa.Column('is_defined', sa.Boolean(), default=False),
        sa.ForeignKeyConstraint(['file_id'], ['files.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create the symbol_tables table
    op.create_table('symbol_tables',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('file_id', sa.Integer(), nullable=False),
        sa.Column('cmd', sa.Integer(), nullable=False),
        sa.Column('cmdsize', sa.Integer(), nullable=False),
        sa.Column('symoff', sa.Integer(), nullable=False),
        sa.Column('nsyms', sa.Integer(), nullable=False),
        sa.Column('stroff', sa.Integer(), nullable=False),
        sa.Column('strsize', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['file_id'], ['files.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create the dynamic_symbol_tables table
    op.create_table('dynamic_symbol_tables',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('file_id', sa.Integer(), nullable=False),
        sa.Column('cmd', sa.Integer(), nullable=False),
        sa.Column('cmdsize', sa.Integer(), nullable=False),
        sa.Column('ilocalsym', sa.Integer(), nullable=False),
        sa.Column('nlocalsym', sa.Integer(), nullable=False),
        sa.Column('iextdefsym', sa.Integer(), nullable=False),
        sa.Column('nextdefsym', sa.Integer(), nullable=False),
        sa.Column('iundefsym', sa.Integer(), nullable=False),
        sa.Column('nundefsym', sa.Integer(), nullable=False),
        sa.Column('tocoff', sa.Integer(), nullable=False),
        sa.Column('ntoc', sa.Integer(), nullable=False),
        sa.Column('modtaboff', sa.Integer(), nullable=False),
        sa.Column('nmodtab', sa.Integer(), nullable=False),
        sa.Column('extrefsymoff', sa.Integer(), nullable=False),
        sa.Column('nextrefsyms', sa.Integer(), nullable=False),
        sa.Column('indirectsymoff', sa.Integer(), nullable=False),
        sa.Column('nindirectsyms', sa.Integer(), nullable=False),
        sa.Column('extreloff', sa.Integer(), nullable=False),
        sa.Column('nextrel', sa.Integer(), nullable=False),
        sa.Column('locreloff', sa.Integer(), nullable=False),
        sa.Column('nlocrel', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['file_id'], ['files.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create the cross_references table
    op.create_table('cross_references',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('file_id', sa.Integer(), nullable=False),
        sa.Column('source_type', sa.String(20), nullable=False),
        sa.Column('source_id', sa.Integer(), nullable=False),
        sa.Column('target_type', sa.String(20), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('address', sa.BigInteger(), nullable=True),
        sa.Column('reference_type', sa.String(20), nullable=False),
        sa.ForeignKeyConstraint(['file_id'], ['files.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('cross_references')
    op.drop_table('dynamic_symbol_tables')
    op.drop_table('symbol_tables')
    op.drop_table('symbols') 