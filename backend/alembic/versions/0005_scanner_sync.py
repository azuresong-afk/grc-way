"""Обновление справочника мер из API «Сканера»: сравнения и отметка синхронизации.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("ref_profiles", sa.Column("scanner_synced_at", sa.DateTime(timezone=True)))
    op.create_table(
        "ref_sync_diffs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("source", sa.String(500), nullable=False),
        sa.Column("payload", _JSON, nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("diff", _JSON, nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.Column("applied_by", sa.Uuid()),
        sa.Column("applied_by_name", sa.String(200)),
        sa.Column("applied", _JSON),
    )
    op.create_index("ix_ref_sync_diffs_created", "ref_sync_diffs", ["created_at"])


def downgrade() -> None:
    op.drop_table("ref_sync_diffs")
    with op.batch_alter_table("ref_profiles") as batch:
        batch.drop_column("scanner_synced_at")
