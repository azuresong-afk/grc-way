"""Справочник Методики оценки угроз 2021: последствия, нарушители, тактики и техники.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)
_KINDS = "'consequence_type', 'consequence', 'capability', 'intruder', 'tactic', 'technique'"


def upgrade() -> None:
    op.create_table(
        "ref_threat_items",
        sa.Column("code", sa.String(32), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("parent_code", sa.String(32)),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(1000), nullable=False),
        sa.Column("description", sa.String(4000)),
        sa.Column("attrs", _JSON, nullable=False),
        sa.Column("source", _JSON, nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("verified_by", sa.Uuid()),
        sa.Column("verified_by_name", sa.String(200)),
        sa.Column("verified_at", _TS),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("file_hash", sa.String(64)),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.CheckConstraint(f"kind IN ({_KINDS})", name="ck_ref_threat_items_kind"),
        sa.CheckConstraint(
            "origin IN ('stub', 'official', 'local')", name="ck_ref_threat_items_origin"
        ),
    )
    op.create_index("ix_ref_threat_items_kind", "ref_threat_items", ["kind", "position"])


def downgrade() -> None:
    op.drop_index("ix_ref_threat_items_kind", table_name="ref_threat_items")
    op.drop_table("ref_threat_items")
