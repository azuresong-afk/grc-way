"""Сформированные документы комплекта (задача 3.1).

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "object_id", sa.Uuid(), sa.ForeignKey("objects.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "project_id",
            sa.Uuid(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("doc_type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("template_name", sa.String(200), nullable=False),
        sa.Column("template_sha256", sa.String(64), nullable=False),
        sa.Column("context_hash", sa.String(64), nullable=False),
        sa.Column("context", _JSON, nullable=False),
        sa.Column("field_map", _JSON, nullable=False),
        sa.Column("unverified", _JSON, nullable=False),
        sa.Column("watermark", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("watermark_reasons", _JSON, nullable=False),
        sa.Column("docx_sha256", sa.String(64), nullable=False),
        sa.Column("docx_size", sa.BigInteger(), nullable=False),
        sa.Column("pdf_sha256", sa.String(64)),
        sa.Column("pdf_size", sa.BigInteger()),
        sa.Column("pdf_error", sa.String(1000)),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.CheckConstraint("status IN ('draft', 'review', 'approved')", name="ck_documents_status"),
        sa.CheckConstraint("version >= 1", name="ck_documents_version"),
    )
    op.create_index(
        "ux_documents_version", "documents", ["object_id", "doc_type", "version"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ux_documents_version", table_name="documents")
    op.drop_table("documents")
