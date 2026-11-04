"""Модель угроз объекта: версии с шагами мастера, угрозы БДУ с решением об актуальности.

Справочник Методики 2021 получает два вида записей: виды воздействия (impact) и
способы реализации угроз (method).

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)
_OLD_KINDS = "'consequence_type', 'consequence', 'capability', 'intruder', 'tactic', 'technique'"
_NEW_KINDS = _OLD_KINDS + ", 'impact', 'method'"


def _set_kinds(kinds: str) -> None:
    with op.batch_alter_table("ref_threat_items") as batch:
        batch.drop_constraint("ck_ref_threat_items_kind", type_="check")
        batch.create_check_constraint("ck_ref_threat_items_kind", f"kind IN ({kinds})")


def upgrade() -> None:
    _set_kinds(_NEW_KINDS)

    op.create_table(
        "threat_models",
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
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("steps", _JSON, nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.Column("based_on", sa.Uuid()),
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
            "status IN ('draft', 'approved', 'superseded')", name="ck_threat_models_status"
        ),
        sa.CheckConstraint(
            "status = 'draft' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)",
            name="ck_threat_models_approved",
        ),
        # Самоутверждение запрещено и на уровне БД, а не только в API.
        sa.CheckConstraint(
            "approved_by IS NULL OR created_by IS NULL OR approved_by <> created_by",
            name="ck_threat_models_not_self_approved",
        ),
    )
    op.create_index(
        "ux_threat_models_version", "threat_models", ["object_id", "version"], unique=True
    )

    op.create_table(
        "threat_model_threats",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "model_id",
            sa.Uuid(),
            sa.ForeignKey("threat_models.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("threat_code", sa.String(16), nullable=False),
        sa.Column("relevant", sa.Boolean()),
        sa.Column("justification", sa.String(4000)),
        sa.Column("intruders", _JSON, nullable=False),
        sa.Column("objects", _JSON, nullable=False),
        sa.Column("consequences", _JSON, nullable=False),
        sa.Column("methods", _JSON, nullable=False),
        sa.Column("tactics", _JSON, nullable=False),
        sa.Column("linked_findings", _JSON, nullable=False),
        sa.Column("added_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by_name", sa.String(200)),
    )
    op.create_index(
        "ux_threat_model_threats_code",
        "threat_model_threats",
        ["model_id", "threat_code"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_threat_model_threats_code", table_name="threat_model_threats")
    op.drop_table("threat_model_threats")
    op.drop_index("ux_threat_models_version", table_name="threat_models")
    op.drop_table("threat_models")
    op.execute("DELETE FROM ref_threat_items WHERE kind IN ('impact', 'method')")
    _set_kinds(_OLD_KINDS)
