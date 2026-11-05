"""Шаблоны документов: свой фирменный шаблон, шрифт комплекта (задача 3.2).

- document_templates — загруженные пользователем шаблоны DOCX по коду документа
  каталога. Действующий — не более одного на документ (active); прежние
  остаются в истории. Файл — в томе GRC_DOCUMENTS_DIR/templates под sha256.
- objects.doc_font — шрифт документов объекта для встроенных шаблонов
  (astra — PT Astra Serif, inter — Inter); NULL — по умолчанию (PT Astra Serif).
- documents.font, documents.template_id — с каким шрифтом и по какому
  шаблону собрана версия (template_id NULL — встроенный шаблон).

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "document_templates",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("doc_type", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("variables", _JSON, nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("comment", sa.String(1000)),
        sa.Column("uploaded_at", _TS, nullable=False),
        sa.Column("uploaded_by", sa.Uuid()),
        sa.Column("uploaded_by_name", sa.String(200)),
        sa.Column("deactivated_at", _TS),
        sa.Column("deactivated_by_name", sa.String(200)),
    )
    op.create_index("ix_document_templates_type", "document_templates", ["doc_type", "uploaded_at"])
    op.create_index(
        "ux_document_templates_active",
        "document_templates",
        ["doc_type"],
        unique=True,
        postgresql_where=sa.text("active"),
        sqlite_where=sa.text("active"),
    )
    with op.batch_alter_table("objects") as b:
        b.add_column(sa.Column("doc_font", sa.String(16)))
    with op.batch_alter_table("documents") as b:
        b.add_column(sa.Column("font", sa.String(16)))
        b.add_column(sa.Column("template_id", sa.Uuid()))


def downgrade() -> None:
    with op.batch_alter_table("documents") as b:
        b.drop_column("template_id")
        b.drop_column("font")
    with op.batch_alter_table("objects") as b:
        b.drop_column("doc_font")
    op.drop_index("ux_document_templates_active", table_name="document_templates")
    op.drop_index("ix_document_templates_type", table_name="document_templates")
    op.drop_table("document_templates")
