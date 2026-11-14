FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src:/app/deploy
WORKDIR /app
COPY deploy/requirements.server.lock /app/deploy/requirements.server.lock
RUN python -m pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: -r /app/deploy/requirements.server.lock
COPY src /app/src
COPY migrations /app/migrations
COPY alembic.ini pyproject.toml README.md /app/
COPY examples/false_reward_pytest /app/examples/false_reward_pytest
COPY deploy/archive_api.py /app/deploy/archive_api.py
RUN mkdir -p /var/lib/autoseal && chown 10001:10001 /var/lib/autoseal
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "archive_api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
