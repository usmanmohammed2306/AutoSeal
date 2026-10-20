"""Alembic environment. The database URL comes from local configuration."""

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from autoseal.db import Base


config = context.config
target_metadata = Base.metadata


def database_url() -> str:
    url = os.environ.get("AUTOSEAL_DATABASE_URL")
    if not url:
        raise RuntimeError("AUTOSEAL_DATABASE_URL is required for migrations")
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(), target_metadata=target_metadata,
        literal_binds=True, dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    config.set_main_option("sqlalchemy.url", database_url().replace("%", "%%"))
    engine = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.", poolclass=pool.NullPool,
    )
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
