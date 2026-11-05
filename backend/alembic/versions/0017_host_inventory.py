"""Данные инвентаризации хоста для I_infr: тип компонента и доступность из
сети «Интернет» (задача 2.7).

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # NULL — не указано: так расчёт отличает «не заполнено» от «недоступен».
    op.add_column("object_hosts", sa.Column("component_types", _JSON))
    op.add_column("object_hosts", sa.Column("internet_exposed", sa.Boolean()))


def downgrade() -> None:
    op.drop_column("object_hosts", "internet_exposed")
    op.drop_column("object_hosts", "component_types")
