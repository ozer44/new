"""hash rest api passwords

Revision ID: hash_rest_api_passwords
Revises: 
Create Date: 2024-03-17 16:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from werkzeug.security import generate_password_hash

# revision identifiers, used by Alembic.
revision = 'hash_rest_api_passwords'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Create a temporary column for the hashed passwords
    op.add_column('rest_api_connections', sa.Column('password_hash', sa.String(128), nullable=True))
    
    # Get the connection and update passwords
    connection = op.get_bind()
    rest_api_connections = connection.execute('SELECT id, password FROM rest_api_connections').fetchall()
    
    for conn in rest_api_connections:
        hashed_password = generate_password_hash(conn[1])
        connection.execute(
            'UPDATE rest_api_connections SET password_hash = %s WHERE id = %s',
            (hashed_password, conn[0])
        )
    
    # Make password_hash not nullable
    op.alter_column('rest_api_connections', 'password_hash',
                    existing_type=sa.String(128),
                    nullable=False)
    
    # Drop the old password column
    op.drop_column('rest_api_connections', 'password')

def downgrade():
    # This is a one-way migration as we can't recover the original passwords
    pass 