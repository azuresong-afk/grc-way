"""Справочник мер: профили, группы, меры, проверки «Сканера», история правок.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_BIGID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "ref_profiles",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("short", sa.String(100), nullable=False),
        sa.Column("document", sa.String(2000)),
        sa.Column("url", sa.String(500)),
        sa.Column("level_label", sa.String(100)),
        sa.Column("levels", _JSON, nullable=False),
        sa.Column("default_level", sa.String(16)),
        sa.Column("dynamic", sa.String(64)),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ref_groups",
        sa.Column(
            "profile_id",
            sa.String(64),
            sa.ForeignKey("ref_profiles.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("code", sa.String(16), primary_key=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
    )
    op.create_table(
        "ref_measures",
        sa.Column(
            "profile_id",
            sa.String(64),
            sa.ForeignKey("ref_profiles.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("group_code", sa.String(16), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("text", sa.String(10000)),
        sa.Column("levels", _JSON, nullable=False),
        sa.Column("checks", _JSON, nullable=False),
        sa.Column("source", _JSON, nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("verified_by", sa.Uuid()),
        sa.Column("verified_by_name", sa.String(200)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.Uuid()),
    )
    op.create_index("ix_ref_measures_group", "ref_measures", ["profile_id", "group_code"])
    op.create_table(
        "ref_checks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("remediation", sa.String(4000)),
        sa.Column("doc", sa.String(500)),
        sa.Column("sources", _JSON, nullable=False),
    )
    op.create_table(
        "ref_revisions",
        sa.Column("id", _BIGID, primary_key=True, autoincrement=True),
        sa.Column("entity", sa.String(32), nullable=False),
        sa.Column("entity_key", sa.String(128), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("data", _JSON, nullable=False),
        sa.Column("changed_by", sa.Uuid()),
        sa.Column("changed_by_name", sa.String(200)),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("comment", sa.String(1000)),
    )
    op.create_index("ix_ref_revisions_entity", "ref_revisions", ["entity", "entity_key"])


def downgrade() -> None:
    op.drop_table("ref_revisions")
    op.drop_table("ref_checks")
    op.drop_table("ref_measures")
    op.drop_table("ref_groups")
    op.drop_table("ref_profiles")
