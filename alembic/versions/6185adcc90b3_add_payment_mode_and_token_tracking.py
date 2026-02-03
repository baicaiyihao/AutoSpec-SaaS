"""add_payment_mode_and_token_tracking

Revision ID: 6185adcc90b3
Revises: a7c439ad7b9e
Create Date: 2026-02-03 11:09:01.888078

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6185adcc90b3'
down_revision: Union[str, Sequence[str], None] = 'a7c439ad7b9e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1. Add PaymentMode enum
    payment_mode_enum = sa.Enum('OWN_KEY', 'PLATFORM_TOKEN', name='paymentmode')
    payment_mode_enum.create(op.get_bind(), checkfirst=True)

    # 2. Add new token tracking columns
    op.add_column('users', sa.Column('tokens_used_own_key', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('tokens_used_platform', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('payment_mode', payment_mode_enum, nullable=False, server_default='OWN_KEY'))


def downgrade() -> None:
    """Downgrade schema."""
    # Remove columns
    op.drop_column('users', 'payment_mode')
    op.drop_column('users', 'tokens_used_platform')
    op.drop_column('users', 'tokens_used_own_key')

    # Drop enum
    sa.Enum(name='paymentmode').drop(op.get_bind(), checkfirst=True)
