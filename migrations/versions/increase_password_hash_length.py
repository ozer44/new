"""increase password hash length

Revision ID: increase_password_hash_length
Revises: hash_rest_api_passwords
Create Date: 2024-03-17 16:35:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'increase_password_hash_length'
down_revision = 'hash_rest_api_passwords'
branch_labels = None
depends_on = None

def upgrade():
    # Alter the password_hash column to increase its length
    op.alter_column('rest_api_connections', 'password_hash',
                    existing_type=sa.String(128),
                    type_=sa.String(256),
                    existing_nullable=False)

def downgrade():
    # Revert the column length back to 128
    op.alter_column('rest_api_connections', 'password_hash',
                    existing_type=sa.String(256),
                    type_=sa.String(128),
                    existing_nullable=False) 