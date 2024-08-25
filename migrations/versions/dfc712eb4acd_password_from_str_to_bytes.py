"""password from str to bytes

Revision ID: dfc712eb4acd
Revises: 2e18b8d0237a
Create Date: 2024-08-02 15:46:08.031353

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dfc712eb4acd'
down_revision: Union[str, None] = '2e18b8d0237a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column(
            'User', 'password',
               existing_type=sa.VARCHAR(length=512),
               type_=sa.LargeBinary(),
               postgresql_using="password::bytea",
               existing_nullable=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('User', 'password',
               existing_type=sa.LargeBinary(),
               type_=sa.VARCHAR(length=512),
               existing_nullable=False)
    # ### end Alembic commands ###
