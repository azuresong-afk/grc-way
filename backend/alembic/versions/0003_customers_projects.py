"""Заказчики, проекты, участники проектов.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "customers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("inn", sa.String(12)),
        sa.Column("ogrn", sa.String(15)),
        sa.Column("address", sa.String(500)),
        sa.Column("contacts", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid()),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("customer_id", sa.Uuid(), sa.ForeignKey("customers.id"), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("contract_ref", sa.String(200)),
        sa.Column("period_from", sa.Date()),
        sa.Column("period_to", sa.Date()),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("platform_project_id", sa.Uuid(), unique=True),
        sa.Column("scanner_engagement_id", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_projects_status", "projects", ["status"])
    op.create_index("ix_projects_customer_id", "projects", ["customer_id"])
    op.create_table(
        "project_members",
        sa.Column(
            "project_id",
            sa.Uuid(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
        ),
    )
    op.create_index("ix_project_members_user_id", "project_members", ["user_id"])


def downgrade() -> None:
    op.drop_table("project_members")
    op.drop_table("projects")
    op.drop_table("customers")
