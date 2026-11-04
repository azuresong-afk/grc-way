"""Ручная оценка: файлы доказательств, отзыв доказательств, подтверждение меры.

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)
_STATUSES = "'implemented', 'partial', 'not_implemented', 'not_applicable'"


def upgrade() -> None:
    op.create_table(
        "files",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "project_id",
            sa.Uuid(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("ext", sa.String(8), nullable=False),
        sa.Column("mime", sa.String(100), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("created_by_name", sa.String(200)),
        sa.CheckConstraint("size > 0", name="ck_files_size"),
    )
    op.create_index("ix_files_sha256", "files", ["sha256"])

    with op.batch_alter_table("evidence") as batch:
        batch.add_column(sa.Column("file_id", sa.Uuid()))
        batch.add_column(sa.Column("withdrawn_at", _TS))
        batch.add_column(sa.Column("withdrawn_by_name", sa.String(200)))
        batch.add_column(sa.Column("withdraw_reason", sa.String(1000)))
        batch.create_foreign_key("fk_evidence_file", "files", ["file_id"], ["id"])
        # Доказательство-файл всегда ссылается на файл.
        batch.create_check_constraint("ck_evidence_file", "kind <> 'file' OR file_id IS NOT NULL")
        # Автоматические доказательства не отзываются: снимок неизменяем.
        batch.create_check_constraint(
            "ck_evidence_withdraw", "kind <> 'scanner' OR withdrawn_at IS NULL"
        )

    with op.batch_alter_table("object_measures") as batch:
        batch.add_column(sa.Column("confirmed_at", _TS))
        batch.add_column(sa.Column("confirmed_by", sa.Uuid()))
        batch.add_column(sa.Column("confirmed_by_name", sa.String(200)))
        batch.add_column(sa.Column("confirmed_status", sa.String(16)))
        batch.add_column(sa.Column("confirm_comment", sa.String(2000)))
        batch.add_column(
            sa.Column("confirmed_evidence", _JSON, nullable=False, server_default="[]")
        )
        # «Не оценена» не подтверждается; подтверждение без статуса не бывает.
        batch.create_check_constraint(
            "ck_object_measures_confirmed",
            f"(confirmed_at IS NULL AND confirmed_status IS NULL) OR "
            f"(confirmed_at IS NOT NULL AND confirmed_status IN ({_STATUSES}))",
        )


def downgrade() -> None:
    with op.batch_alter_table("object_measures") as batch:
        batch.drop_constraint("ck_object_measures_confirmed", type_="check")
        batch.drop_column("confirmed_evidence")
        batch.drop_column("confirm_comment")
        batch.drop_column("confirmed_status")
        batch.drop_column("confirmed_by_name")
        batch.drop_column("confirmed_by")
        batch.drop_column("confirmed_at")
    with op.batch_alter_table("evidence") as batch:
        batch.drop_constraint("ck_evidence_withdraw", type_="check")
        batch.drop_constraint("ck_evidence_file", type_="check")
        batch.drop_constraint("fk_evidence_file", type_="foreignkey")
        batch.drop_column("withdraw_reason")
        batch.drop_column("withdrawn_by_name")
        batch.drop_column("withdrawn_at")
        batch.drop_column("file_id")
    op.drop_index("ix_files_sha256", table_name="files")
    op.drop_table("files")
