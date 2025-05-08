"""Add fat binary support

Revision ID: add_fat_binary_support
Revises: 0089bf4129d5
Create Date: 2025-05-15

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_fat_binary_support'
down_revision = '0089bf4129d5'  # Link to the initial migration
branch_labels = None
depends_on = None


def upgrade():
    # Add is_fat_binary column to files table
    op.add_column('files', sa.Column('is_fat_binary', sa.Boolean(), nullable=True, server_default='0'))
    
    # Add arch_offset and arch_size columns to headers table
    op.add_column('headers', sa.Column('arch_offset', sa.Integer(), nullable=True))
    op.add_column('headers', sa.Column('arch_size', sa.Integer(), nullable=True))


def downgrade():
    # Remove columns added in upgrade
    op.drop_column('headers', 'arch_size')
    op.drop_column('headers', 'arch_offset')
    op.drop_column('files', 'is_fat_binary') 