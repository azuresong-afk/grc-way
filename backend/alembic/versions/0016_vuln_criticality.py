"""Методика оценки критичности уязвимостей 2025 и нормативные документы (задача 2.6).

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)
_ORIGIN = "origin IN ('stub', 'official', 'local')"


def _verification() -> list[sa.Column]:
    return [
        sa.Column("verified_by", sa.Uuid()),
        sa.Column("verified_by_name", sa.String(200)),
        sa.Column("verified_at", _TS),
        sa.Column("revision", sa.Integer(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "ref_vuln_methodologies",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("definition", _JSON, nullable=False),
        sa.Column("definition_hash", sa.String(64), nullable=False),
        sa.Column("source", _JSON, nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        *_verification(),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("imported_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.CheckConstraint(_ORIGIN, name="ck_ref_vuln_methodologies_origin"),
    )
    op.create_table(
        "ref_documents",
        sa.Column("code", sa.String(64), primary_key=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("short", sa.String(200), nullable=False),
        sa.Column("title", sa.String(1000), nullable=False),
        sa.Column("issuer", sa.String(200)),
        sa.Column("issued", sa.Date()),
        sa.Column("number", sa.String(32)),
        sa.Column("url", sa.String(500)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("replaced_by", sa.String(64)),
        sa.Column("source", _JSON, nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        *_verification(),
        sa.Column("file_hash", sa.String(64)),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.CheckConstraint(
            "status IN ('active', 'not_applicable')", name="ck_ref_documents_status"
        ),
        sa.CheckConstraint(_ORIGIN, name="ck_ref_documents_origin"),
    )


def downgrade() -> None:
    op.drop_table("ref_documents")
    op.drop_table("ref_vuln_methodologies")
