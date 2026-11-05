"""Реестр уязвимостей объекта и оценки критичности по Методике 2025 (задача 2.8).

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "object_vulns",
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
        sa.Column("bdu_id", sa.String(32)),
        sa.Column("title", sa.String(2000), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("manual_source", sa.String(16)),
        sa.Column("manual_hosts", _JSON, nullable=False),
        sa.Column("scanner_hosts", _JSON, nullable=False),
        sa.Column("scanner_findings", _JSON, nullable=False),
        sa.Column("snapshot_id", sa.Uuid()),
        sa.Column("snapshot_number", sa.Integer()),
        sa.Column("last_seen_snapshot", sa.Integer()),
        sa.Column("cvss_choice", _JSON),
        sa.Column("e_choice", _JSON, nullable=False),
        sa.Column("h_choice", _JSON, nullable=False),
        sa.Column("certified_szi", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("comment", sa.String(2000)),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.Column("updated_by_name", sa.String(200)),
        sa.CheckConstraint("origin IN ('scanner', 'manual')", name="ck_object_vulns_origin"),
        sa.CheckConstraint(
            "bdu_id IS NOT NULL OR origin = 'manual'", name="ck_object_vulns_bdu_or_manual"
        ),
    )
    op.create_index("ix_object_vulns_object", "object_vulns", ["object_id"])
    op.create_index("ix_object_vulns_bdu", "object_vulns", ["bdu_id"])
    # Одна запись на идентификатор БДУ в объекте.
    op.create_index(
        "ux_object_vulns_bdu",
        "object_vulns",
        ["object_id", "bdu_id"],
        unique=True,
        postgresql_where=sa.text("bdu_id IS NOT NULL"),
        sqlite_where=sa.text("bdu_id IS NOT NULL"),
    )

    op.create_table(
        "object_vuln_assessments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "vuln_id",
            sa.Uuid(),
            sa.ForeignKey("object_vulns.id", ondelete="CASCADE"),
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
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("reasons", _JSON, nullable=False),
        sa.Column("hosts", _JSON, nullable=False),
        sa.Column("inputs", _JSON, nullable=False),
        sa.Column("outcome", _JSON, nullable=False),
        sa.Column("details", _JSON, nullable=False),
        sa.Column("v", sa.String(16), nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("level_title", sa.String(100), nullable=False),
        sa.Column("deadline_at", _TS, nullable=False),
        sa.Column("deadline_from", sa.Integer(), nullable=False),
        sa.Column("methodology_id", sa.String(32), nullable=False),
        sa.Column("methodology_version", sa.String(64), nullable=False),
        sa.Column("methodology_revision", sa.Integer(), nullable=False),
        sa.Column("methodology_hash", sa.String(64), nullable=False),
        sa.Column("snapshot_id", sa.Uuid()),
        sa.Column("snapshot_number", sa.Integer()),
        sa.Column("bdu_changed_at", _TS),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("assessed_at", _TS, nullable=False),
        sa.Column("assessed_by", sa.Uuid()),
        sa.Column("assessed_by_name", sa.String(200)),
    )
    op.create_index(
        "ux_object_vuln_assessments",
        "object_vuln_assessments",
        ["vuln_id", "number"],
        unique=True,
    )

    # Оценка неизменяема: повторный расчёт — новая запись.
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            """
            CREATE FUNCTION object_vuln_assessments_immutable() RETURNS trigger AS $$
            BEGIN
              RAISE EXCEPTION 'object_vuln_assessments are immutable';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            "CREATE TRIGGER object_vuln_assessments_no_update BEFORE UPDATE ON "
            "object_vuln_assessments FOR EACH ROW EXECUTE FUNCTION "
            "object_vuln_assessments_immutable();"
        )
    elif dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER object_vuln_assessments_no_update BEFORE UPDATE ON "
            "object_vuln_assessments BEGIN "
            "SELECT RAISE(ABORT, 'object_vuln_assessments are immutable'); END;"
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    op.execute(
        "DROP TRIGGER IF EXISTS object_vuln_assessments_no_update ON object_vuln_assessments"
        if dialect == "postgresql"
        else "DROP TRIGGER IF EXISTS object_vuln_assessments_no_update"
    )
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS object_vuln_assessments_immutable()")
    op.drop_index("ux_object_vuln_assessments", table_name="object_vuln_assessments")
    op.drop_table("object_vuln_assessments")
    op.drop_index("ux_object_vulns_bdu", table_name="object_vulns")
    op.drop_index("ix_object_vulns_bdu", table_name="object_vulns")
    op.drop_index("ix_object_vulns_object", table_name="object_vulns")
    op.drop_table("object_vulns")
