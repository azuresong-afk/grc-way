"""СЗИ: реестр сертифицированных СЗИ (загрузки и записи) и СЗИ объектов (задача 2.5).

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "szi_imports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("file_name", sa.String(255), nullable=False),
        sa.Column("file_sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("file_ext", sa.String(8), nullable=False),
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
        sa.CheckConstraint("file_ext IN ('csv', 'xlsx')", name="ck_szi_imports_ext"),
        sa.CheckConstraint(
            "status IN ('pending', 'applied', 'superseded')", name="ck_szi_imports_status"
        ),
    )
    op.create_index("ix_szi_imports_created", "szi_imports", ["created_at"])

    op.create_table(
        "szi_registry",
        sa.Column("cert_number", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(2000), nullable=False),
        sa.Column("registered_on", sa.Date()),
        sa.Column("valid_to", sa.Date()),
        sa.Column("valid_to_raw", sa.String(500)),
        sa.Column("requirements", sa.Text()),
        sa.Column("scheme", sa.Text()),
        sa.Column("lab", sa.Text()),
        sa.Column("cert_body", sa.Text()),
        sa.Column("applicant", sa.Text()),
        sa.Column("applicant_details", sa.Text()),
        sa.Column("support_until", sa.Date()),
        sa.Column("support_raw", sa.String(1000)),
        sa.Column("note", sa.Text()),
        sa.Column("cert_status", sa.String(16), nullable=False),
        sa.Column("trust_level", sa.Integer()),
        sa.Column("profiles", _JSON, nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False),
        sa.Column("first_version", sa.Date()),
        sa.Column("changed_version", sa.Date()),
        sa.Column("first_import_id", sa.Uuid(), nullable=False),
        sa.Column("changed_import_id", sa.Uuid(), nullable=False),
        sa.Column("withdrawn_at", _TS),
        sa.Column("withdrawn_import_id", sa.Uuid()),
        sa.Column("updated_at", _TS, nullable=False),
        sa.CheckConstraint(
            "cert_status IN ('active', 'suspended', 'terminated')",
            name="ck_szi_registry_status",
        ),
    )
    op.create_index("ix_szi_registry_valid_to", "szi_registry", ["valid_to"])

    op.create_table(
        "object_szi",
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
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("vendor", sa.String(300)),
        sa.Column("version", sa.String(100)),
        sa.Column("cert_number", sa.String(32)),
        sa.Column("cert_valid_to", sa.Date()),
        sa.Column("trust_level", sa.Integer()),
        sa.Column("protection_class", sa.String(200)),
        sa.Column("placement", sa.String(2000)),
        sa.Column("measure_ids", _JSON, nullable=False),
        sa.Column("comment", sa.String(2000)),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by", sa.Uuid()),
        sa.Column("updated_by_name", sa.String(200)),
        sa.CheckConstraint(
            "trust_level IS NULL OR trust_level BETWEEN 1 AND 6", name="ck_object_szi_trust"
        ),
    )
    op.create_index("ix_object_szi_object", "object_szi", ["object_id"])
    op.create_index("ix_object_szi_cert", "object_szi", ["cert_number"])


def downgrade() -> None:
    op.drop_index("ix_object_szi_cert", table_name="object_szi")
    op.drop_index("ix_object_szi_object", table_name="object_szi")
    op.drop_table("object_szi")
    op.drop_index("ix_szi_registry_valid_to", table_name="szi_registry")
    op.drop_table("szi_registry")
    op.drop_index("ix_szi_imports_created", table_name="szi_imports")
    op.drop_table("szi_imports")
