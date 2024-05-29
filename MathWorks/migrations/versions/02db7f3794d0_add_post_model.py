"""Add Post model

Revision ID: 02db7f3794d0
Revises: 
Create Date: 2024-05-27 14:55:01.112252

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '02db7f3794d0'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_admin', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('is_admin')

    # ### end Alembic commands ###
