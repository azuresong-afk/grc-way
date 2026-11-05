"""Режим «Платформы»: теневые пользователи и проекты, outbox событий (задача 3.5).

- users: platform_typ (user | service), последние роли и проекты из токена
  (только для выбора адресатов уведомлений — права всегда из токена запроса),
  platform_seen_at.
- projects.platform_synced_at — когда тень проекта сверялась с платформой.
- outbox — события для POST {PLATFORM_EVENTS_URL}: тело хранится байт в байт,
  как оно подписывается и уходит в сеть; повторы 1/5/15/60 мин.
- assessment_feed — последнее отправленное grc.assessment.updated по объекту
  (не чаще раза в минуту, только последнее значение).

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TS = sa.DateTime(timezone=True)
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("users") as b:
        b.add_column(sa.Column("platform_typ", sa.String(16)))
        b.add_column(sa.Column("platform_roles", _JSON))
        b.add_column(sa.Column("platform_projects", _JSON))
        b.add_column(sa.Column("platform_seen_at", _TS))
    with op.batch_alter_table("projects") as b:
        b.add_column(sa.Column("platform_synced_at", _TS))

    op.create_table(
        "outbox",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64)),
        sa.Column("subject", sa.String(200)),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_at", _TS, nullable=False),
        sa.Column("last_error", sa.String(500)),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("delivered_at", _TS),
        sa.CheckConstraint(
            "status IN ('pending', 'delivered', 'rejected', 'dead')", name="ck_outbox_status"
        ),
    )
    op.create_index("ix_outbox_due", "outbox", ["status", "next_at"])
    op.create_index("ix_outbox_created", "outbox", ["created_at"])

    op.create_table(
        "assessment_feed",
        sa.Column(
            "object_id",
            sa.Uuid,
            sa.ForeignKey("objects.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("percent", sa.Integer),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("sent_at", _TS, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("assessment_feed")
    op.drop_index("ix_outbox_created", table_name="outbox")
    op.drop_index("ix_outbox_due", table_name="outbox")
    op.drop_table("outbox")
    with op.batch_alter_table("projects") as b:
        b.drop_column("platform_synced_at")
    with op.batch_alter_table("users") as b:
        b.drop_column("platform_seen_at")
        b.drop_column("platform_projects")
        b.drop_column("platform_roles")
        b.drop_column("platform_typ")
