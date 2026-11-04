"""Снимки результатов прогонов «Сканера», доказательства, автостатус мер.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)
_STATUSES = "'implemented', 'partial', 'not_implemented', 'not_applicable', 'unassessed'"


def upgrade() -> None:
    op.create_table(
        "scanner_snapshots",
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
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("run_name", sa.String(300)),
        sa.Column("run_status", sa.String(32), nullable=False),
        sa.Column("run_started_at", _TS),
        sa.Column("run_finished_at", _TS),
        sa.Column("run_modules", _JSON, nullable=False),
        sa.Column("selection", sa.String(8), nullable=False),
        sa.Column("profile_id", sa.String(64), nullable=False),
        sa.Column("level", sa.String(16)),
        sa.Column("adaptation_version", sa.Integer()),
        sa.Column("percent", sa.Float()),
        sa.Column("counts", _JSON, nullable=False),
        sa.Column("compliance", _JSON, nullable=False),
        sa.Column("coverage", _JSON, nullable=False),
        sa.Column("object_hosts", _JSON, nullable=False),
        sa.Column("summary", _JSON, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("source", sa.String(300), nullable=False),
        sa.Column("imported_at", _TS, nullable=False),
        sa.Column("imported_by", sa.Uuid()),
        sa.Column("imported_by_name", sa.String(200)),
        sa.CheckConstraint("selection IN ('latest', 'manual')", name="ck_scanner_snapshots_sel"),
    )
    op.create_index(
        "ix_scanner_snapshots_object", "scanner_snapshots", ["object_id", "imported_at"]
    )
    op.create_index(
        "ux_scanner_snapshots_number", "scanner_snapshots", ["object_id", "number"], unique=True
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "object_measure_id",
            sa.Uuid(),
            sa.ForeignKey("object_measures.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "object_id", sa.Uuid(), sa.ForeignKey("objects.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "project_id",
            sa.Uuid(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("measure_id", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column(
            "snapshot_id", sa.Uuid(), sa.ForeignKey("scanner_snapshots.id", ondelete="CASCADE")
        ),
        sa.Column("status", sa.String(16)),
        sa.Column("summary", sa.String(1000), nullable=False),
        sa.Column("data", _JSON, nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.CheckConstraint(
            "kind IN ('scanner', 'file', 'interview', 'inspection', 'certificate')",
            name="ck_evidence_kind",
        ),
        # Автоматическое доказательство всегда ссылается на снимок.
        sa.CheckConstraint(
            "kind <> 'scanner' OR snapshot_id IS NOT NULL", name="ck_evidence_scanner_snapshot"
        ),
        sa.CheckConstraint(f"status IS NULL OR status IN ({_STATUSES})", name="ck_evidence_status"),
    )
    op.create_index("ix_evidence_measure", "evidence", ["object_measure_id", "created_at"])
    op.create_index("ix_evidence_snapshot", "evidence", ["snapshot_id"])

    with op.batch_alter_table("object_measures") as batch:
        batch.add_column(sa.Column("status_source", sa.String(8)))
        batch.add_column(sa.Column("auto_status", sa.String(16)))
        batch.add_column(sa.Column("auto_note", sa.String(1000)))
        batch.add_column(sa.Column("auto_snapshot_id", sa.Uuid()))
        batch.create_foreign_key(
            "fk_object_measures_auto_snapshot",
            "scanner_snapshots",
            ["auto_snapshot_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_check_constraint(
            "ck_object_measures_status_source",
            "status_source IS NULL OR status_source IN ('auto', 'manual')",
        )
        batch.create_check_constraint(
            "ck_object_measures_auto_status", f"auto_status IS NULL OR auto_status IN ({_STATUSES})"
        )

    # Снимок неизменяем: UPDATE запрещён на уровне БД (удаление — только вместе с объектом).
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            """
            CREATE FUNCTION scanner_snapshots_immutable() RETURNS trigger AS $$
            BEGIN
              RAISE EXCEPTION 'scanner_snapshots are immutable';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            "CREATE TRIGGER scanner_snapshots_no_update BEFORE UPDATE ON scanner_snapshots "
            "FOR EACH ROW EXECUTE FUNCTION scanner_snapshots_immutable();"
        )
    elif dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER scanner_snapshots_no_update BEFORE UPDATE ON scanner_snapshots "
            "BEGIN SELECT RAISE(ABORT, 'scanner_snapshots are immutable'); END;"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    op.execute(
        "DROP TRIGGER IF EXISTS scanner_snapshots_no_update ON scanner_snapshots"
        if dialect == "postgresql"
        else "DROP TRIGGER IF EXISTS scanner_snapshots_no_update"
    )
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS scanner_snapshots_immutable()")
    with op.batch_alter_table("object_measures") as batch:
        batch.drop_constraint("ck_object_measures_auto_status", type_="check")
        batch.drop_constraint("ck_object_measures_status_source", type_="check")
        batch.drop_constraint("fk_object_measures_auto_snapshot", type_="foreignkey")
        batch.drop_column("auto_snapshot_id")
        batch.drop_column("auto_note")
        batch.drop_column("auto_status")
        batch.drop_column("status_source")
    op.drop_index("ix_evidence_snapshot", table_name="evidence")
    op.drop_index("ix_evidence_measure", table_name="evidence")
    op.drop_table("evidence")
    op.drop_index("ux_scanner_snapshots_number", table_name="scanner_snapshots")
    op.drop_index("ix_scanner_snapshots_object", table_name="scanner_snapshots")
    op.drop_table("scanner_snapshots")
