"""Классификация: таблицы как данные, расчёты объектов, утверждение.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "ref_classification_tables",
        sa.Column("regime", sa.String(8), primary_key=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("definition", _JSON, nullable=False),
        sa.Column("definition_hash", sa.String(64), nullable=False),
        sa.Column("source", _JSON, nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("verified_by", sa.Uuid()),
        sa.Column("verified_by_name", sa.String(200)),
        sa.Column("verified_at", _TS),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("imported_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.CheckConstraint(
            "regime IN ('117', '21', '239')", name="ck_ref_classification_tables_regime"
        ),
    )

    op.create_table(
        "classifications",
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
        sa.Column("regime", sa.String(8), nullable=False),
        sa.Column("inputs", _JSON, nullable=False),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("result_label", sa.String(200), nullable=False),
        sa.Column("step_values", _JSON, nullable=False),
        sa.Column("trace", _JSON, nullable=False),
        sa.Column("justification", sa.String(10000)),
        sa.Column("table_version", sa.String(64), nullable=False),
        sa.Column("table_revision", sa.Integer(), nullable=False),
        sa.Column("table_hash", sa.String(64), nullable=False),
        sa.Column("table_snapshot", _JSON, nullable=False),
        sa.Column("table_verified", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.Column("approved_at", _TS),
        sa.Column("approved_by", sa.Uuid()),
        sa.Column("approved_by_name", sa.String(200)),
        sa.Column("approval_comment", sa.String(2000)),
        sa.Column("unverified_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("superseded_at", _TS),
        sa.Column("superseded_by", sa.Uuid()),
        sa.CheckConstraint(
            "status IN ('draft', 'approved', 'superseded')", name="ck_classifications_status"
        ),
        sa.CheckConstraint(
            "status <> 'approved' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)",
            name="ck_classifications_approved",
        ),
        # Самоутверждение запрещено и на уровне БД, а не только в API.
        sa.CheckConstraint(
            "approved_by IS NULL OR created_by IS NULL OR approved_by <> created_by",
            name="ck_classifications_not_self_approved",
        ),
    )
    op.create_index("ix_classifications_object", "classifications", ["object_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_classifications_object", table_name="classifications")
    op.drop_table("classifications")
    op.drop_table("ref_classification_tables")
