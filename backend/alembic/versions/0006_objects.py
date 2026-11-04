"""Объекты проекта: описание, сегменты, хосты (вручную и из активов «Сканера»).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "objects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "project_id",
            sa.Uuid(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("regime", sa.String(8)),
        sa.Column("purpose", sa.String(4000)),
        sa.Column("boundaries", sa.String(4000)),
        sa.Column("interconnections", _JSON, nullable=False),
        sa.Column("internet", sa.Boolean(), nullable=False),
        sa.Column("responsible", _JSON, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.Column("scanner_synced_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("kind IN ('gis', 'ispdn', 'kii', 'other')", name="ck_objects_kind"),
        sa.CheckConstraint(
            "regime IS NULL OR regime IN ('117', '21', '239')", name="ck_objects_regime"
        ),
    )
    op.create_index("ix_objects_project", "objects", ["project_id", "status"])

    op.create_table(
        "object_segments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "object_id",
            sa.Uuid(),
            sa.ForeignKey("objects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(2000)),
        sa.Column("scanner_group", sa.String(200)),
        sa.Column("position", sa.Integer(), nullable=False),
    )
    op.create_index("ix_object_segments_object", "object_segments", ["object_id"])

    op.create_table(
        "object_hosts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "object_id",
            sa.Uuid(),
            sa.ForeignKey("objects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            sa.Uuid(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "segment_id", sa.Uuid(), sa.ForeignKey("object_segments.id", ondelete="SET NULL")
        ),
        sa.Column("address", sa.String(64), nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("role", sa.String(300)),
        sa.Column("os", sa.String(200)),
        sa.Column("os_family", sa.String(32)),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("scanner_asset_id", sa.Integer()),
        sa.Column("scanner_groups", _JSON, nullable=False),
        sa.Column("criticality", sa.String(16)),
        sa.Column("owner", sa.String(200)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("scanner_missing", sa.Boolean(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("source IN ('manual', 'scanner')", name="ck_object_hosts_source"),
    )
    op.create_index(
        "ux_object_hosts_address", "object_hosts", ["object_id", "address"], unique=True
    )
    op.create_index("ix_object_hosts_project_address", "object_hosts", ["project_id", "address"])


def downgrade() -> None:
    op.drop_table("object_hosts")
    op.drop_table("object_segments")
    op.drop_table("objects")
