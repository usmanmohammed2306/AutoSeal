from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


ROOT = Path(__file__).resolve().parents[2]


def test_initial_migration_up_and_down(tmp_path: Path, monkeypatch) -> None:
    url = f"sqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setenv("AUTOSEAL_DATABASE_URL", url)
    config = Config(str(ROOT / "alembic.ini"))
    command.upgrade(config, "head")
    engine = create_engine(url)
    assert {"runs", "run_events", "alembic_version"}.issubset(inspect(engine).get_table_names())
    command.downgrade(config, "base")
    assert "runs" not in inspect(engine).get_table_names()
    engine.dispose()
