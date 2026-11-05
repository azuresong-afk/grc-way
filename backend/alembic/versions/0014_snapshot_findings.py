"""Находки «Сканера» с идентификаторами БДУ в снимке прогона (задача 2.4).

Снимок неизменяем, поэтому находки пишутся в него при импорте целиком. У снимков,
сделанных до этой миграции, поле пустое (NULL) — «находки не импортировались»,
это отличается от пустого списка «находок с БДУ нет».

Колонка добавляется без пересоздания таблицы (не batch), чтобы не потерять
триггер неизменяемости на SQLite.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("scanner_snapshots", sa.Column("findings", _JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("scanner_snapshots", "findings")
