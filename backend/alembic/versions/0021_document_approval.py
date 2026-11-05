"""Согласование документов и история согласования (задача 3.3).

- documents: статус «заменён» (superseded) — прежняя утверждённая версия после
  утверждения новой; кто и когда отправил на согласование, утвердил; комментарий
  утверждающего; утверждено ли по несверенным записям справочников; когда
  заменён; файлы проекта (draft_docx_sha256, draft_pdf_sha256) — утверждение
  пересобирает документ без отметки «Проект», файлы проекта остаются в томе.
- Самоутверждение запрещено и в базе: утверждающий не автор версии и не тот,
  кто отправил её на согласование.
- document_reviews — история: отправлен, возвращён (с причиной), утверждён,
  заменён.

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    with op.batch_alter_table("documents") as b:
        b.drop_constraint("ck_documents_status", type_="check")
        b.add_column(sa.Column("submitted_at", _TS))
        b.add_column(sa.Column("submitted_by", sa.Uuid()))
        b.add_column(sa.Column("submitted_by_name", sa.String(200)))
        b.add_column(sa.Column("approved_at", _TS))
        b.add_column(sa.Column("approved_by", sa.Uuid()))
        b.add_column(sa.Column("approved_by_name", sa.String(200)))
        b.add_column(sa.Column("approval_comment", sa.String(2000)))
        b.add_column(
            sa.Column(
                "unverified_acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()
            )
        )
        b.add_column(sa.Column("superseded_at", _TS))
        b.add_column(sa.Column("draft_docx_sha256", sa.String(64)))
        b.add_column(sa.Column("draft_pdf_sha256", sa.String(64)))
        b.create_check_constraint(
            "ck_documents_status", "status IN ('draft', 'review', 'approved', 'superseded')"
        )
        b.create_check_constraint(
            "ck_documents_approved",
            "status NOT IN ('approved', 'superseded') "
            "OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)",
        )
        b.create_check_constraint(
            "ck_documents_not_self",
            "approved_by IS NULL OR ((created_by IS NULL OR approved_by <> created_by) "
            "AND (submitted_by IS NULL OR approved_by <> submitted_by))",
        )
    op.create_table(
        "document_reviews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "document_id",
            sa.Uuid(),
            sa.ForeignKey("documents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=False),
        sa.Column("to_status", sa.String(16), nullable=False),
        sa.Column("comment", sa.String(2000)),
        sa.Column("actor_id", sa.Uuid()),
        sa.Column("actor_name", sa.String(200)),
        sa.Column("at", _TS, nullable=False),
        sa.CheckConstraint(
            "action IN ('submit', 'return', 'approve', 'supersede')",
            name="ck_document_reviews_action",
        ),
    )
    op.create_index("ix_document_reviews_doc", "document_reviews", ["document_id", "at"])


def downgrade() -> None:
    op.drop_index("ix_document_reviews_doc", table_name="document_reviews")
    op.drop_table("document_reviews")
    op.execute("UPDATE documents SET status = 'approved' WHERE status = 'superseded'")
    with op.batch_alter_table("documents") as b:
        b.drop_constraint("ck_documents_not_self", type_="check")
        b.drop_constraint("ck_documents_approved", type_="check")
        b.drop_constraint("ck_documents_status", type_="check")
        for col in (
            "draft_pdf_sha256",
            "draft_docx_sha256",
            "superseded_at",
            "unverified_acknowledged",
            "approval_comment",
            "approved_by_name",
            "approved_by",
            "approved_at",
            "submitted_by_name",
            "submitted_by",
            "submitted_at",
        ):
            b.drop_column(col)
        b.create_check_constraint(
            "ck_documents_status", "status IN ('draft', 'review', 'approved')"
        )
