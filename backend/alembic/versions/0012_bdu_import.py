"""БДУ ФСТЭК: загрузки выгрузок, угрозы (thrlist.xlsx), уязвимости (vullist.xlsx).

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def _record_columns() -> list[sa.Column]:
    return [
        sa.Column("row_hash", sa.String(64), nullable=False),
        sa.Column("first_version", sa.Date()),
        sa.Column("changed_version", sa.Date()),
        sa.Column("first_import_id", sa.Uuid(), nullable=False),
        sa.Column("changed_import_id", sa.Uuid(), nullable=False),
        sa.Column("withdrawn_at", _TS),
        sa.Column("withdrawn_import_id", sa.Uuid()),
        sa.Column("updated_at", _TS, nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "bdu_imports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("file_name", sa.String(255), nullable=False),
        sa.Column("file_sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("export_version", sa.Date()),
        sa.Column("version_source", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("summary", _JSON, nullable=False),
        sa.Column("items", _JSON, nullable=False),
        sa.Column("warnings", _JSON, nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.Column("applied_at", _TS),
        sa.Column("applied_by", sa.Uuid()),
        sa.Column("applied_by_name", sa.String(200)),
        sa.Column("applied", _JSON),
        sa.CheckConstraint("kind IN ('threats', 'vulns')", name="ck_bdu_imports_kind"),
        sa.CheckConstraint(
            "status IN ('pending', 'applied', 'superseded')", name="ck_bdu_imports_status"
        ),
    )
    op.create_index("ix_bdu_imports_kind", "bdu_imports", ["kind", "created_at"])

    op.create_table(
        "bdu_threats",
        sa.Column("code", sa.String(16), primary_key=True),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(1000), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("source", sa.Text()),
        sa.Column("target", sa.Text()),
        sa.Column("conf", sa.Boolean()),
        sa.Column("integ", sa.Boolean()),
        sa.Column("avail", sa.Boolean()),
        sa.Column("published_on", sa.Date()),
        sa.Column("changed_on", sa.Date()),
        sa.Column("status", sa.Text()),
        *_record_columns(),
    )

    op.create_table(
        "bdu_vulns",
        sa.Column("bdu_id", sa.String(32), primary_key=True),
        sa.Column("title", sa.String(2000), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("vendor", sa.Text()),
        sa.Column("product", sa.Text()),
        sa.Column("product_version", sa.Text()),
        sa.Column("sw_type", sa.Text()),
        sa.Column("platform", sa.Text()),
        sa.Column("vuln_class", sa.Text()),
        sa.Column("identified_on", sa.Date()),
        sa.Column("published_on", sa.Date()),
        sa.Column("severity", sa.Text()),
        sa.Column("cvss3_vector", sa.String(200)),
        sa.Column("cvss3_version", sa.String(8)),
        sa.Column("cvss3_score", sa.Float()),
        sa.Column("cvss3_score_source", sa.String(16)),
        sa.Column("cvss_other", _JSON),
        sa.Column("measures", sa.Text()),
        sa.Column("status", sa.Text()),
        sa.Column("exploit", sa.String(16)),
        sa.Column("exploit_raw", sa.String(500)),
        sa.Column("in_wild", sa.String(16)),
        sa.Column("in_wild_raw", sa.String(500)),
        sa.Column("fix_info", sa.Text()),
        sa.Column("links", sa.Text()),
        sa.Column("cve_ids", _JSON, nullable=False),
        sa.Column("cwe_ids", _JSON, nullable=False),
        sa.Column("other_ids", sa.Text()),
        sa.Column("other_info", sa.Text()),
        sa.Column("exploit_method", sa.Text()),
        sa.Column("fix_method", sa.Text()),
        sa.Column("crit_hash", sa.String(64), nullable=False),
        sa.Column("criticality_changed_at", _TS),
        sa.Column("criticality_changed_import_id", sa.Uuid()),
        sa.Column("criticality_changes", _JSON),
        *_record_columns(),
    )
    op.create_index("ix_bdu_vulns_crit_changed", "bdu_vulns", ["criticality_changed_at"])


def downgrade() -> None:
    op.drop_index("ix_bdu_vulns_crit_changed", table_name="bdu_vulns")
    op.drop_table("bdu_vulns")
    op.drop_table("bdu_threats")
    op.drop_index("ix_bdu_imports_kind", table_name="bdu_imports")
    op.drop_table("bdu_imports")
