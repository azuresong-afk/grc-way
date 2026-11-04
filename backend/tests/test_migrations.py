"""Страж цепочки миграций: имена 0001_…, одна голова, без пропусков и ветвлений."""

import re
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

BACKEND = Path(__file__).resolve().parents[1]


def _script() -> ScriptDirectory:
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    return ScriptDirectory.from_config(cfg)


def test_single_head_and_sequential_numbers():
    script = _script()
    assert len(script.get_heads()) == 1, "несколько голов: миграции разветвились"

    chain = list(reversed(list(script.walk_revisions())))
    for i, rev in enumerate(chain, start=1):
        expected = f"{i:04d}"
        assert rev.revision == expected, f"ожидалась ревизия {expected}, найдена {rev.revision}"
        prev = None if i == 1 else f"{i - 1:04d}"
        assert rev.down_revision == prev
        assert re.fullmatch(rf"{expected}_[a-z0-9_]+\.py", Path(rev.path).name)


def test_upgrade_and_downgrade_on_sqlite(tmp_path):
    from alembic import command

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{tmp_path / 'm.db'}")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
