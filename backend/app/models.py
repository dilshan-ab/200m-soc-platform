"""SQLAlchemy models. All timestamps are timezone-aware UTC (see UTCDateTime)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class UTCDateTime(TypeDecorator):
    """Stores UTC, always returns timezone-aware datetimes (SQLite drops tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):  # type: ignore[override]
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect):  # type: ignore[override]
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def _pk() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=new_id)


def _ts() -> Mapped[datetime]:
    return mapped_column(UTCDateTime, default=utcnow)


# --------------------------------------------------------------------------- identity
class Client(Base):
    __tablename__ = "clients"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(120), unique=True)
    code: Mapped[str] = mapped_column(String(32), unique=True)
    kind: Mapped[str] = mapped_column(String(20), default="client")  # client | business_unit
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    owner: Mapped[str] = mapped_column(String(120), default="")
    report_recipients: Mapped[list[Any]] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = _ts()


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _pk()
    subject: Mapped[str] = mapped_column(String(255), unique=True)  # OIDC sub, or "dev:<email>"
    email: Mapped[str] = mapped_column(String(255), unique=True)
    name: Mapped[str] = mapped_column(String(160), default="")
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    grants: Mapped[list[Any]] = mapped_column(JSON, default=list)  # explicit extra capabilities, beyond the role default
    denied: Mapped[list[Any]] = mapped_column(JSON, default=list)  # explicit restrictions, below the role default (superadmin only sets this)
    all_clients: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # dev-mode credentials only (never populated when AUTH_MODE=oidc)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = _ts()


class ClientMembership(Base):
    __tablename__ = "client_memberships"
    __table_args__ = (UniqueConstraint("user_id", "client_id"),)
    id: Mapped[str] = _pk()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = _pk()
    sid_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = _ts()
    last_seen_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    step_up_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    oidc_sid: Mapped[str | None] = mapped_column(String(255), nullable=True)


class OidcState(Base):
    __tablename__ = "oidc_states"
    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(20), default="login")  # login | step_up
    return_to: Mapped[str] = mapped_column(String(255), default="/")
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[str] = _pk()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(12))
    scopes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- integrations
class Server(Base):
    __tablename__ = "servers"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(120), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default="monitored")  # soc_core|monitored|workstation_group|proxy|dns
    environment: Mapped[str] = mapped_column(String(30), default="production")
    owner: Mapped[str] = mapped_column(String(120), default="")
    criticality: Mapped[str] = mapped_column(String(10), default="medium")
    os: Mapped[str] = mapped_column(String(80), default="")
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="unknown")  # up|down|degraded|unknown
    status_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expected_controls: Mapped[list[Any]] = mapped_column(JSON, default=list)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()


class Tool(Base):
    """An installed integration instance (secrets live in the secret store, never here)."""

    __tablename__ = "tools"
    id: Mapped[str] = _pk()
    type: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    server_id: Mapped[str | None] = mapped_column(ForeignKey("servers.id"), nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_refs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # field -> secret ref
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft|tested|enabled|paused|disabled
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    poll_interval: Mapped[int] = mapped_column(Integer, default=30)
    severity_map: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    field_map: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    mapping_version: Mapped[int] = mapped_column(Integer, default=1)
    config_version: Mapped[int] = mapped_column(Integer, default=1)
    webhook_secret_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    webhook_auth_mode: Mapped[str] = mapped_column(String(10), default="hmac")  # hmac | bearer
    last_test: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    version_info: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = _ts()
    state: Mapped[ConnectorState | None] = relationship(
        back_populates="tool", uselist=False, cascade="all, delete-orphan"
    )


class ConnectorState(Base):
    __tablename__ = "connector_state"
    tool_id: Mapped[str] = mapped_column(ForeignKey("tools.id", ondelete="CASCADE"), primary_key=True)
    checkpoint: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_error: Mapped[str] = mapped_column(String(500), default="")
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    items_total: Mapped[int] = mapped_column(Integer, default=0)
    items_today: Mapped[int] = mapped_column(Integer, default=0)
    items_day: Mapped[str] = mapped_column(String(10), default="")
    lag_seconds: Mapped[int] = mapped_column(Integer, default=0)
    tool: Mapped[Tool] = relationship(back_populates="state")


class WebhookReplay(Base):
    __tablename__ = "webhook_replay"
    id: Mapped[str] = _pk()
    tool_id: Mapped[str] = mapped_column(String(36), index=True)
    digest: Mapped[str] = mapped_column(String(64))
    seen_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("tool_id", "digest"),)


class SecretRecord(Base):
    __tablename__ = "secrets"
    ref: Mapped[str] = mapped_column(String(120), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- assets
class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ips: Mapped[list[Any]] = mapped_column(JSON, default=list)
    os: Mapped[str] = mapped_column(String(120), default="")
    kind: Mapped[str] = mapped_column(String(20), default="workstation")  # workstation | server
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    agent_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    server_id: Mapped[str | None] = mapped_column(ForeignKey("servers.id"), nullable=True)
    owner: Mapped[str] = mapped_column(String(120), default="")
    department: Mapped[str] = mapped_column(String(120), default="")
    criticality: Mapped[str] = mapped_column(String(10), default="medium")
    sca_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    software: Mapped[list[Any]] = mapped_column(JSON, default=list)
    ports: Mapped[list[Any]] = mapped_column(JSON, default=list)
    last_backup_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    patch_status: Mapped[str] = mapped_column(String(30), default="unknown")
    decommissioned: Mapped[bool] = mapped_column(Boolean, default=False)
    source_ids: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- alerts / cases
class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_status_sev", "status", "severity"),
        Index("ix_alert_dedup", "dedup_key", "last_seen"),
    )
    id: Mapped[str] = _pk()
    tool_id: Mapped[str | None] = mapped_column(ForeignKey("tools.id"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(40), default="manual")
    source_id: Mapped[str] = mapped_column(String(200), default="")
    time: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    severity: Mapped[str] = mapped_column(String(10), default="low", index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    rule_id: Mapped[str] = mapped_column(String(80), default="", index=True)
    mitre: Mapped[list[Any]] = mapped_column(JSON, default=list)
    compliance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    host: Mapped[str] = mapped_column(String(255), default="", index=True)
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    dst_ip: Mapped[str] = mapped_column(String(64), default="")
    username: Mapped[str] = mapped_column(String(160), default="")
    file_hash: Mapped[str] = mapped_column(String(128), default="")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    dedup_key: Mapped[str] = mapped_column(String(64), default="")
    count: Mapped[int] = mapped_column(Integer, default=1)
    category: Mapped[str] = mapped_column(String(20), default="security")  # security | infrastructure
    ack_due: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolve_due: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    sla_policy_version: Mapped[int] = mapped_column(Integer, default=0)
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False)
    tuning_note: Mapped[str] = mapped_column(Text, default="")
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)


class AlertReceipt(Base):
    """Deduplication receipt: the same source event arriving via poll and webhook is stored once."""

    __tablename__ = "alert_receipts"
    __table_args__ = (UniqueConstraint("tool_id", "source_id"),)
    id: Mapped[str] = _pk()
    tool_id: Mapped[str] = mapped_column(String(36))
    source_id: Mapped[str] = mapped_column(String(200))
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    received_at: Mapped[datetime] = _ts()


class SavedView(Base):
    __tablename__ = "saved_views"
    id: Mapped[str] = _pk()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    scope: Mapped[str] = mapped_column(String(20), default="alerts")
    filters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = _pk()
    number: Mapped[int] = mapped_column(Integer, index=True, default=0)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open|in_progress|resolved|closed
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    template: Mapped[str] = mapped_column(String(80), default="")
    tlp: Mapped[str] = mapped_column(String(10), default="AMBER")
    pap: Mapped[str] = mapped_column(String(10), default="AMBER")
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    external_id: Mapped[str | None] = mapped_column(String(80), nullable=True)  # TheHive id
    sync_status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|synced|failed|conflict
    sync_error: Mapped[str] = mapped_column(String(500), default="")
    resolution: Mapped[str] = mapped_column(String(40), default="")
    lessons: Mapped[str] = mapped_column(Text, default="")
    ack_due: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolve_due: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    tasks: Mapped[list[CaseTask]] = relationship(back_populates="case", cascade="all, delete-orphan")
    observables: Mapped[list[CaseObservable]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    timeline: Mapped[list[CaseEvent]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseEvent.at"
    )


class CaseTask(Base):
    __tablename__ = "case_tasks"
    id: Mapped[str] = _pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(20), default="todo")  # todo|in_progress|done
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    case: Mapped[Case] = relationship(back_populates="tasks")


class CaseObservable(Base):
    __tablename__ = "case_observables"
    id: Mapped[str] = _pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(20))  # ip|domain|hash|url|user|email|host
    value: Mapped[str] = mapped_column(String(500))
    verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tlp: Mapped[str] = mapped_column(String(10), default="AMBER")
    case: Mapped[Case] = relationship(back_populates="observables")


class CaseEvent(Base):
    __tablename__ = "case_events"
    id: Mapped[str] = _pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = _ts()
    actor: Mapped[str] = mapped_column(String(160), default="system")
    kind: Mapped[str] = mapped_column(String(30), default="note")
    message: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    case: Mapped[Case] = relationship(back_populates="timeline")


class CaseTicket(Base):
    __tablename__ = "case_tickets"
    id: Mapped[str] = _pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(20), default="clickup")
    external_id: Mapped[str] = mapped_column(String(80), default="")
    url: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(40), default="open")


class CaseTemplate(Base):
    __tablename__ = "case_templates"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    tasks: Mapped[list[Any]] = mapped_column(JSON, default=list)
    runbook_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    external_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)


class Runbook(Base):
    __tablename__ = "runbooks"
    id: Mapped[str] = _pk()
    slug: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(20), default="guide")  # guide | template
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft | published | archived
    body: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("slug", "version"),)


# --------------------------------------------------------------------------- response / approvals
class ActionRequest(Base):
    __tablename__ = "action_requests"
    id: Mapped[str] = _pk()
    action_key: Mapped[str] = mapped_column(String(60), index=True)
    targets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64))
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(24), default="pending_approval", index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approvals_required: Mapped[int] = mapped_column(Integer, default=1)
    policy_version: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)  # approval window
    revert_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)  # auto-unblock
    external_operation_id: Mapped[str] = mapped_column(String(120), default="")
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    automation_rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    __table_args__ = (UniqueConstraint("requester_id", "idempotency_key"),)


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (UniqueConstraint("request_id", "approver_id"),)
    id: Mapped[str] = _pk()
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id", ondelete="CASCADE"), index=True)
    approver_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[str] = mapped_column(String(10))  # approve | reject
    reason: Mapped[str] = mapped_column(Text, default="")
    payload_hash: Mapped[str] = mapped_column(String(64))
    decided_at: Mapped[datetime] = _ts()


class ApprovalRequest(Base):
    """Approvals for non-action changes (integration enable, retention, role change, restore...)."""

    __tablename__ = "change_requests"
    id: Mapped[str] = _pk()
    kind: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64))
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|rejected|applied|expired|failed
    reason: Mapped[str] = mapped_column(Text, default="")
    approvals_required: Mapped[int] = mapped_column(Integer, default=1)
    approvers: Mapped[list[Any]] = mapped_column(JSON, default=list)
    decision_reason: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = _ts()
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


# --------------------------------------------------------------------------- vulnerabilities / compliance
class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "vuln_id", "component"),)
    id: Mapped[str] = _pk()
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    vuln_id: Mapped[str] = mapped_column(String(60), index=True)  # CVE-... or OID
    component: Mapped[str] = mapped_column(String(200), default="")
    title: Mapped[str] = mapped_column(String(400), default="")
    severity: Mapped[str] = mapped_column(String(10), default="medium", index=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    sources: Mapped[list[Any]] = mapped_column(JSON, default=list)
    owner: Mapped[str] = mapped_column(String(120), default="")
    deadline: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    first_seen: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()
    remediation_request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class ControlResult(Base):
    __tablename__ = "control_results"
    __table_args__ = (UniqueConstraint("framework", "control_id", "asset_id"),)
    id: Mapped[str] = _pk()
    framework: Mapped[str] = mapped_column(String(30), index=True)  # pci_dss|gdpr|iso27001|cis
    control_id: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(300), default="")
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    status: Mapped[str] = mapped_column(String(10), default="unknown")  # pass|fail|unknown
    source: Mapped[str] = mapped_column(String(40), default="wazuh_sca")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    checked_at: Mapped[datetime] = _ts()


class ControlException(Base):
    __tablename__ = "control_exceptions"
    id: Mapped[str] = _pk()
    framework: Mapped[str] = mapped_column(String(30))
    control_id: Mapped[str] = mapped_column(String(60))
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reason: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str] = mapped_column(String(160), default="")
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- intel / hunts / reports
class EnrichmentJob(Base):
    __tablename__ = "enrichment_jobs"
    id: Mapped[str] = _pk()
    indicator: Mapped[str] = mapped_column(String(500))
    indicator_type: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|done|failed
    results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tlp: Mapped[str] = mapped_column(String(10), default="AMBER")
    created_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Hunt(Base):
    __tablename__ = "hunts"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(20), default="search")  # search (query over ingested alerts) | collection (Velociraptor artifact pull)
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    technique_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    query: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    artifact: Mapped[str] = mapped_column(String(120), default="")
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    targets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(24), default="draft")  # draft|pending_approval|active|concluded|...(mirrors ActionRequest.status for collection hunts)
    verdict: Mapped[str] = mapped_column(String(20), default="")  # ""|true_positive|false_positive|inconclusive
    conclusion_note: Mapped[str] = mapped_column(Text, default="")
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    client_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    results: Mapped[list[Any]] = mapped_column(JSON, default=list)
    external_id: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = _ts()
    concluded_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class ReportJob(Base):
    __tablename__ = "report_jobs"
    id: Mapped[str] = _pk()
    kind: Mapped[str] = mapped_column(String(40))  # soc_metrics|compliance|vulnerabilities|client|case
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fmt: Mapped[str] = mapped_column(String(10), default="html")  # html|csv|json|pdf
    status: Mapped[str] = mapped_column(String(20), default="queued")
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    client_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    artifact_path: Mapped[str] = mapped_column(String(400), default="")
    checksum: Mapped[str] = mapped_column(String(64), default="")
    error: Mapped[str] = mapped_column(String(400), default="")
    template_version: Mapped[int] = mapped_column(Integer, default=1)
    metric_version: Mapped[int] = mapped_column(Integer, default=1)
    schedule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurrence: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = _ts()
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class ReportSchedule(Base):
    __tablename__ = "report_schedules"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(40))
    cadence: Mapped[str] = mapped_column(String(12))  # daily|weekly|monthly|quarterly
    timezone: Mapped[str] = mapped_column(String(60), default="Asia/Colombo")
    hour: Mapped[int] = mapped_column(Integer, default=7)
    fmt: Mapped[str] = mapped_column(String(10), default="html")
    recipients: Mapped[list[Any]] = mapped_column(JSON, default=list)
    client_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(20), default="")
    created_at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- policies / automation / notifications
class SlaPolicy(Base):
    __tablename__ = "sla_policies"
    id: Mapped[str] = _pk()
    version: Mapped[int] = mapped_column(Integer, default=1, unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    targets: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # severity -> {ack_minutes, resolve_minutes}
    pause_statuses: Mapped[list[Any]] = mapped_column(JSON, default=list)
    effective_from: Mapped[datetime] = _ts()
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(160), default="")


class AutomationRule(Base):
    __tablename__ = "automation_rules"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(160), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    trigger: Mapped[str] = mapped_column(String(30), default="alert.created")
    conditions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    actions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    client_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    max_per_hour: Mapped[int] = mapped_column(Integer, default=30)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = _ts()


class AutomationRun(Base):
    __tablename__ = "automation_runs"
    id: Mapped[str] = _pk()
    rule_id: Mapped[str] = mapped_column(ForeignKey("automation_rules.id", ondelete="CASCADE"), index=True)
    event_ref: Mapped[str] = mapped_column(String(80))
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    matched: Mapped[bool] = mapped_column(Boolean, default=False)
    outcome: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="done")
    created_at: Mapped[datetime] = _ts()


class NotificationRule(Base):
    __tablename__ = "notification_rules"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(160), unique=True)
    event_types: Mapped[list[Any]] = mapped_column(JSON, default=list)  # alert.created, server.down, ...
    min_severity: Mapped[str] = mapped_column(String(10), default="high")
    categories: Mapped[list[Any]] = mapped_column(JSON, default=list)
    client_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    destinations: Mapped[list[Any]] = mapped_column(JSON, default=list)  # destination ids
    escalate_after_minutes: Mapped[int] = mapped_column(Integer, default=0)
    escalation_destinations: Mapped[list[Any]] = mapped_column(JSON, default=list)
    quiet_hours: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    detail_level: Mapped[str] = mapped_column(String(10), default="summary")  # summary | full
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class NotificationDestination(Base):
    __tablename__ = "notification_destinations"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(160), unique=True)
    channel: Mapped[str] = mapped_column(String(12))  # slack|telegram|email|clickup
    tool_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    address: Mapped[str] = mapped_column(String(300), default="")  # channel id / chat id / recipient
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    id: Mapped[str] = _pk()
    rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    destination_id: Mapped[str] = mapped_column(String(36))
    event_ref: Mapped[str] = mapped_column(String(80))
    dedupe_key: Mapped[str] = mapped_column(String(120), unique=True)
    subject: Mapped[str] = mapped_column(String(300), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|sent|failed|dead
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(String(300), default="")
    escalation_level: Mapped[int] = mapped_column(Integer, default=0)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


# --------------------------------------------------------------------------- platform
class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = _ts()
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    action: Mapped[str] = mapped_column(String(80), index=True)
    resource_type: Mapped[str] = mapped_column(String(40), default="")
    resource_id: Mapped[str] = mapped_column(String(80), default="")
    outcome: Mapped[str] = mapped_column(String(20), default="success")
    client_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")
    forwarded: Mapped[bool] = mapped_column(Boolean, default=False)


class Setting(Base):
    __tablename__ = "platform_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    id: Mapped[str] = _pk()
    dataset: Mapped[str] = mapped_column(String(30), unique=True)  # alerts|cases|audit|raw_events|reports
    days: Mapped[int] = mapped_column(Integer, default=90)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class Outbox(Base):
    """Transactional outbox: work committed with the business change, dispatched by workers."""

    __tablename__ = "outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(12), default="pending", index=True)  # pending|done|dead
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    run_after: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    last_error: Mapped[str] = mapped_column(String(400), default="")
    created_at: Mapped[datetime] = _ts()


class BootstrapState(Base):
    __tablename__ = "bootstrap_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    steps: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class BackupJob(Base):
    __tablename__ = "backup_jobs"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(160))
    component: Mapped[str] = mapped_column(String(40))  # postgres|vault|config|reports|search
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------- playbooks (visual SOAR)
class Playbook(Base):
    __tablename__ = "playbooks"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    trigger: Mapped[str] = mapped_column(String(40), default="manual")  # manual | alert.created | case.created | scheduled
    nodes: Mapped[list[Any]] = mapped_column(JSON, default=list)  # [{id, type, position:{x,y}, data:{…}}]
    edges: Mapped[list[Any]] = mapped_column(JSON, default=list)  # [{id, source, target, sourceHandle, targetHandle, label}]
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)  # draft | published | archived
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    runs: Mapped[list["PlaybookRun"]] = relationship(back_populates="playbook", cascade="all, delete-orphan")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    id: Mapped[str] = _pk()
    playbook_id: Mapped[str] = mapped_column(ForeignKey("playbooks.id", ondelete="CASCADE"), index=True)
    trigger_ref: Mapped[str] = mapped_column(String(120), default="")  # alert:<id> or case:<id> or manual
    status: Mapped[str] = mapped_column(String(20), default="running", index=True)  # running | paused | completed | failed | cancelled
    current_node: Mapped[str] = mapped_column(String(60), default="")
    execution_log: Mapped[list[Any]] = mapped_column(JSON, default=list)  # [{node_id, type, status, started_at, finished_at, result}]
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = _ts()
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    playbook: Mapped["Playbook"] = relationship(back_populates="runs")


# --------------------------------------------------------------------------- alert correlation engine
class CorrelationRule(Base):
    __tablename__ = "correlation_rules"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    strategy: Mapped[str] = mapped_column(String(30), default="ioc_overlap")  # ioc_overlap | time_window | kill_chain | threshold
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # config schema per strategy:
    #   ioc_overlap:  {fields: ["src_ip","dst_ip","host","username","file_hash"], min_shared: 2, window_minutes: 60}
    #   time_window:  {window_minutes: 15, min_alerts: 3, group_by: ["host","client_id"]}
    #   kill_chain:   {tactics: ["initial-access","execution","persistence"], window_minutes: 120, same_host: true}
    #   threshold:    {field: "rule_id", threshold: 10, window_minutes: 30, group_by: ["client_id"]}
    severity_boost: Mapped[int] = mapped_column(Integer, default=1)  # how many levels to escalate the incident severity
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open | investigating | resolved | false_positive
    rule_id: Mapped[str | None] = mapped_column(ForeignKey("correlation_rules.id"), nullable=True, index=True)
    rule_name: Mapped[str] = mapped_column(String(200), default="")
    strategy: Mapped[str] = mapped_column(String(30), default="manual")
    alert_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    shared_iocs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # {field: [values]} — the IOCs that linked these alerts
    kill_chain_stages: Mapped[list[Any]] = mapped_column(JSON, default=list)  # MITRE tactics seen across correlated alerts
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    first_alert_time: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_alert_time: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class SigmaRule(Base):
    """An imported Sigma detection rule: https://github.com/SigmaHQ/sigma"""

    __tablename__ = "sigma_rules"
    id: Mapped[str] = _pk()
    sigma_id: Mapped[str] = mapped_column(String(64), default="", index=True)  # the rule's own "id:" field, if present
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="experimental", index=True)  # stable|test|experimental|deprecated|unsupported
    level: Mapped[str] = mapped_column(String(10), default="medium")  # informational|low|medium|high|critical
    log_source: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # {product, service, category}
    technique_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)  # parsed from attack.t#### tags
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)  # full raw tag list
    references: Mapped[list[Any]] = mapped_column(JSON, default=list)
    false_positives: Mapped[list[Any]] = mapped_column(JSON, default=list)
    raw_yaml: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    imported_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class CaseEvidence(Base):
    __tablename__ = "case_evidence"
    id: Mapped[str] = _pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(300))
    type: Mapped[str] = mapped_column(String(30), default="file")  # file|screenshot|pcap|log|artifact|note
    description: Mapped[str] = mapped_column(Text, default="")
    hash_sha256: Mapped[str] = mapped_column(String(64), default="")
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    storage_ref: Mapped[str] = mapped_column(String(500), default="")
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    collected_by: Mapped[str] = mapped_column(String(160), default="")
    collected_at: Mapped[datetime] = _ts()
    chain_of_custody: Mapped[list[Any]] = mapped_column(JSON, default=list)
    observable_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    created_at: Mapped[datetime] = _ts()


class EntityProfile(Base):
    __tablename__ = "entity_profiles"
    __table_args__ = (UniqueConstraint("entity_type", "entity_value", "client_id"),)
    id: Mapped[str] = _pk()
    entity_type: Mapped[str] = mapped_column(String(20), index=True)  # user|host|ip
    entity_value: Mapped[str] = mapped_column(String(255), index=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    baseline: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    anomalies: Mapped[list[Any]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
