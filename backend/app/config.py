"""Application configuration, loaded from environment variables (prefix SOC_)."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./soc.db"
    redis_url: str | None = None

    # --- Authentication -------------------------------------------------
    # "oidc": Keycloak via backend-for-frontend. "dev": local users + TOTP (never in production).
    auth_mode: Literal["oidc", "dev"] = "dev"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    kc_admin_url: str = ""  # internal Keycloak base for the Admin API (service account), e.g. http://keycloak:8080
    kc_realm: str = "soc"
    kc_admin_client_id: str = "soc-admin"
    kc_admin_client_secret: str = ""
    oidc_internal_issuer: str = ""  # optional: reach Keycloak by an internal URL (e.g. http://keycloak:8080/realms/soc) while the public issuer stays the browser URL
    oidc_post_logout_redirect_uri: str = ""
    oidc_client_secret: str = ""  # confidential BFF client; loaded from Vault in production
    oidc_redirect_uri: str = ""
    oidc_role_claim: str = "soc_role"
    oidc_allowed_algs: list[str] = ["RS256", "ES256"]
    oidc_step_up_acr: str = "mfa-webauthn"
    oidc_account_url: str = ""  # self-service account page; defaults to Keycloak's <issuer>/account/ when empty
    oidc_require_email_verification: bool = False  # adds VERIFY_EMAIL to new users' required actions; needs SMTP configured in Keycloak first

    # --- Sessions / cookies ---------------------------------------------
    cookie_secure: bool = True
    session_idle_minutes: int = 15
    session_absolute_hours: int = 8
    max_sessions_per_user: int = 3
    step_up_minutes: int = 20
    step_up_required: bool = False  # true = sensitive admin actions ask for a fresh MFA re-verification first
    allowed_origins: list[str] = ["http://localhost:5173", "http://localhost:8000"]

    # --- Secrets / crypto -----------------------------------------------
    # 32 url-safe base64 bytes (Fernet). Required in production. Used by the local secret store.
    secrets_key: str = ""
    secret_backend: Literal["local", "vault"] = "local"
    vault_addr: str = ""
    vault_token: str = ""
    vault_mount: str = "secret"
    audit_hmac_key: str = ""  # optional keyed hashing for the audit chain

    # --- Operations -----------------------------------------------------
    bootstrap_token: str = ""  # one-time deployment-issued capability for /setup
    metrics_token: str = ""  # bearer token for /metrics
    workers_enabled: bool = True
    keycloak_sync_minutes: int = 15  # scheduled Sync with Keycloak; 0 turns it off
    poll_tick_seconds: int = 5
    outbox_tick_seconds: int = 2
    webhook_max_body_bytes: int = 1_048_576
    webhook_max_skew_seconds: int = 300
    webhook_rate_per_minute: int = 600
    api_rate_per_minute: int = 600
    login_rate_per_minute: int = 10
    # Egress policy for connectors (SSRF protection)
    allow_http_connectors: bool = False
    egress_allowed_suffixes: list[str] = [".corp.local", ".sec.company.local"]
    egress_allowed_cidrs: list[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    report_dir: str = "./reports"
    public_base_url: str = "http://localhost:8000"
    default_timezone: str = "Asia/Colombo"

    # --- AI Copilot -------------------------------------------------------
    llm_provider: Literal["anthropic", "openai", "none"] = "none"
    llm_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"
    llm_max_tokens: int = 2048
    llm_temperature: float = 0.3

    @model_validator(mode="after")
    def _production_guards(self) -> Settings:
        if self.environment == "production":
            problems = []
            if self.auth_mode != "oidc":
                problems.append("SOC_AUTH_MODE must be 'oidc' in production")
            if not self.cookie_secure:
                problems.append("SOC_COOKIE_SECURE must be true in production")
            if not self.secrets_key and self.secret_backend == "local":
                problems.append("SOC_SECRETS_KEY is required for the local secret store")
            if self.allow_http_connectors:
                problems.append("SOC_ALLOW_HTTP_CONNECTORS must be false in production")
            if self.database_url.startswith("sqlite"):
                problems.append("SQLite is not allowed in production; use PostgreSQL")
            if problems:
                raise ValueError("; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
