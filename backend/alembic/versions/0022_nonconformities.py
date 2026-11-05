"""Несоответствия и план устранения, связь с «Устранением» (задача 3.4).

- nonconformities — пункт плана: мера «Не реализована / Частично» или
  обнаруженная уязвимость реестра. План собирается из текущих данных объекта;
  то, что вносит специалист (мероприятие, ответственный, срок, способ
  устранения), и заявка в «Устранении» хранятся здесь. Пункт, источник которого
  перестал быть несоответствием, закрывается, а не удаляется.
- nonconformity_events — история пункта: отправка, статусы заявки, проверка.
- inbox — принятые события «Платформы» / «Устранения» (идемпотентность по id).
- projects.vm_project_id — проект в «Устранении», куда уходят заявки.
- evidence.kind: новое значение remediation — подтверждение устранения
  повторной проверкой в «Устранении».

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_KINDS_OLD = "'scanner', 'file', 'interview', 'inspection', 'certificate'"
_KINDS_NEW = _KINDS_OLD + ", 'remediation'"


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        b.add_column(sa.Column("vm_project_id", sa.String(64)))

    with op.batch_alter_table("evidence") as b:
        b.drop_constraint("ck_evidence_kind", type_="check")
        b.create_check_constraint("ck_evidence_kind", f"kind IN ({_KINDS_NEW})")

    op.create_table(
        "nonconformities",
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
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column(
            "object_measure_id",
            sa.Uuid(),
            sa.ForeignKey("object_measures.id", ondelete="CASCADE"),
        ),
        sa.Column(
            "object_vuln_id", sa.Uuid(), sa.ForeignKey("object_vulns.id", ondelete="CASCADE")
        ),
        sa.Column("ref", sa.String(64), nullable=False),
        sa.Column("title", sa.String(2000), nullable=False),
        sa.Column("source_status", sa.String(16)),
        sa.Column("hosts", _JSON, nullable=False, server_default="[]"),
        sa.Column("details", sa.String(4000)),
        # Уязвимость: копия текущей оценки.
        sa.Column("assessment_id", sa.Uuid()),
        sa.Column("v", sa.String(16)),
        sa.Column("level", sa.String(16)),
        sa.Column("level_title", sa.String(100)),
        sa.Column("assessed_at", _TS),
        sa.Column("deadline_at", _TS),
        sa.Column("certified_szi", sa.Boolean(), nullable=False, server_default=sa.false()),
        # Мера: приоритет и необязательный срок (п. 9 ТЗ — по умолчанию не выводятся).
        sa.Column("priority", sa.String(8)),
        sa.Column("due_date", sa.Date()),
        # Что вносит специалист.
        sa.Column("action", sa.String(2000)),
        sa.Column("responsible", sa.String(300)),
        sa.Column("comment", sa.String(2000)),
        sa.Column("method", sa.String(16)),
        sa.Column("update_origin", sa.String(16)),
        sa.Column("update_tested", sa.Boolean()),
        sa.Column("compensating", _JSON, nullable=False, server_default="[]"),
        # Закрытие: источник перестал быть несоответствием.
        sa.Column("opened_at", _TS, nullable=False),
        sa.Column("closed_at", _TS),
        sa.Column("close_reason", sa.String(500)),
        # «Устранение».
        sa.Column("vm_ticket_id", sa.String(64)),
        sa.Column("vm_project_id", sa.String(64)),
        sa.Column("vm_status", sa.String(32)),
        sa.Column("vm_status_at", _TS),
        sa.Column("vm_verified_result", sa.String(32)),
        sa.Column("vm_verified_at", _TS),
        sa.Column("vm_verified_run_id", sa.String(64)),
        sa.Column("sent_at", _TS),
        sa.Column("sent_by", sa.Uuid()),
        sa.Column("sent_by_name", sa.String(200)),
        sa.Column("sent_hash", sa.String(64)),
        sa.Column("updated_at", _TS, nullable=False),
        sa.Column("updated_by_name", sa.String(200)),
        sa.CheckConstraint("kind IN ('measure', 'vuln')", name="ck_nonconformities_kind"),
        sa.CheckConstraint(
            "(kind = 'measure' AND object_measure_id IS NOT NULL AND object_vuln_id IS NULL) "
            "OR (kind = 'vuln' AND object_vuln_id IS NOT NULL AND object_measure_id IS NULL)",
            name="ck_nonconformities_source",
        ),
        sa.CheckConstraint(
            "method IS NULL OR method IN ('update', 'compensating')",
            name="ck_nonconformities_method",
        ),
        sa.CheckConstraint(
            "priority IS NULL OR priority IN ('high', 'medium', 'low')",
            name="ck_nonconformities_priority",
        ),
    )
    op.create_index("ix_nonconformities_object", "nonconformities", ["object_id"])
    op.create_index(
        "ux_nonconformities_measure", "nonconformities", ["object_measure_id"], unique=True
    )
    op.create_index("ux_nonconformities_vuln", "nonconformities", ["object_vuln_id"], unique=True)
    op.create_index("ix_nonconformities_ticket", "nonconformities", ["vm_ticket_id"])

    op.create_table(
        "nonconformity_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "nonconformity_id",
            sa.Uuid(),
            sa.ForeignKey("nonconformities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("at", _TS, nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("text", sa.String(1000), nullable=False),
        sa.Column("data", _JSON, nullable=False, server_default="{}"),
        sa.Column("actor_name", sa.String(200)),
    )
    op.create_index(
        "ix_nonconformity_events_nc", "nonconformity_events", ["nonconformity_id", "at"]
    )

    op.create_table(
        "inbox",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("received_at", _TS, nullable=False),
        sa.Column("result", sa.String(32), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("inbox")
    op.drop_index("ix_nonconformity_events_nc", table_name="nonconformity_events")
    op.drop_table("nonconformity_events")
    for ix in (
        "ix_nonconformities_ticket",
        "ux_nonconformities_vuln",
        "ux_nonconformities_measure",
        "ix_nonconformities_object",
    ):
        op.drop_index(ix, table_name="nonconformities")
    op.drop_table("nonconformities")
    op.execute("DELETE FROM evidence WHERE kind = 'remediation'")
    with op.batch_alter_table("evidence") as b:
        b.drop_constraint("ck_evidence_kind", type_="check")
        b.create_check_constraint("ck_evidence_kind", f"kind IN ({_KINDS_OLD})")
    with op.batch_alter_table("projects") as b:
        b.drop_column("vm_project_id")
