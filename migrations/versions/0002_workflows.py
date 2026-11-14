"""Durable repair workflows, leases and append-only events."""

from alembic import op
import sqlalchemy as sa

revision = "0002_workflows"
down_revision = "0001_runs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("workflows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("lease_token", sa.String(36)), sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("result_id", sa.String(71)), sa.Column("error", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("kind", "idempotency_key", name="uq_workflow_kind_key"))
    op.create_index("ix_workflows_state", "workflows", ["state"])
    op.create_table("workflow_events", sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workflow_id", sa.String(36), sa.ForeignKey("workflows.id"), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False), sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_workflow_events_workflow_id", "workflow_events", ["workflow_id"])


def downgrade():
    op.drop_index("ix_workflow_events_workflow_id", table_name="workflow_events")
    op.drop_table("workflow_events")
    op.drop_index("ix_workflows_state", table_name="workflows")
    op.drop_table("workflows")
