"""Набор мер объекта и версии адаптации.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "adaptations",
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
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "classification_id",
            sa.Uuid(),
            sa.ForeignKey("classifications.id", ondelete="SET NULL"),
        ),
        sa.Column("profile_id", sa.String(64), nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("level_label", sa.String(200), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.Column("editors", _JSON, nullable=False),
        sa.Column("edits", sa.Integer(), nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("approved_at", _TS),
        sa.Column("approved_by", sa.Uuid()),
        sa.Column("approved_by_name", sa.String(200)),
        sa.Column("approval_comment", sa.String(2000)),
        sa.Column("unverified_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("snapshot", _JSON),
        sa.Column("superseded_at", _TS),
        sa.CheckConstraint(
            "status IN ('draft', 'approved', 'superseded')", name="ck_adaptations_status"
        ),
        sa.CheckConstraint(
            "status = 'draft' OR status = 'superseded' OR "
            "(approved_by IS NOT NULL AND approved_at IS NOT NULL AND snapshot IS NOT NULL)",
            name="ck_adaptations_approved",
        ),
        # Самоутверждение запрещено и на уровне БД (автор версии ≠ утверждающий);
        # остальных правивших проверяет API по списку editors.
        sa.CheckConstraint(
            "approved_by IS NULL OR created_by IS NULL OR approved_by <> created_by",
            name="ck_adaptations_not_self_approved",
        ),
    )
    op.create_index("ux_adaptations_version", "adaptations", ["object_id", "version"], unique=True)

    op.create_table(
        "object_measures",
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
        sa.Column("profile_id", sa.String(64), nullable=False),
        sa.Column("measure_id", sa.String(32), nullable=False),
        sa.Column("group_code", sa.String(16), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("adaptation", sa.String(16), nullable=False),
        sa.Column("adaptation_reason", sa.String(4000)),
        sa.Column("compensating_ids", _JSON, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("comment", sa.String(4000)),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.Column("adapted_at", _TS),
        sa.Column("adapted_by_name", sa.String(200)),
        sa.Column("status_at", _TS),
        sa.Column("status_by_name", sa.String(200)),
        sa.CheckConstraint("origin IN ('baseline', 'added')", name="ck_object_measures_origin"),
        sa.CheckConstraint(
            "adaptation IN ('none', 'excluded', 'compensated')",
            name="ck_object_measures_adaptation",
        ),
        sa.CheckConstraint(
            "status IN ('implemented', 'partial', 'not_implemented', 'not_applicable', "
            "'unassessed')",
            name="ck_object_measures_status",
        ),
        sa.CheckConstraint(
            "method IN ('auto', 'manual', 'mixed')", name="ck_object_measures_method"
        ),
        # Исключить можно только меру базового набора; адаптация — только с обоснованием.
        sa.CheckConstraint(
            "adaptation <> 'excluded' OR origin = 'baseline'",
            name="ck_object_measures_exclude_baseline",
        ),
        sa.CheckConstraint(
            "(adaptation = 'none' AND origin = 'baseline') OR adaptation_reason IS NOT NULL",
            name="ck_object_measures_reason",
        ),
    )
    op.create_index(
        "ux_object_measures_measure",
        "object_measures",
        ["object_id", "profile_id", "measure_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_object_measures_measure", table_name="object_measures")
    op.drop_table("object_measures")
    op.drop_index("ux_adaptations_version", table_name="adaptations")
    op.drop_table("adaptations")
