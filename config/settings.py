"""
Centralized Pydantic Settings for Agentic AI SOC Platform.

All configuration is loaded from .env (or environment variables).
Import `settings` from this module — or from `config` — for access.

Phase 1: Foundation — Feature 16 (config consolidation)
"""

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application-wide settings loaded from .env / environment.

    Precedence: environment variable > .env file > default value.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore unknown env vars
    )

    # ── LLM Provider ──────────────────────────────────────────────────────────
    # Set to "nvidia" | "gemini" | "openai" | "none" | "auto" (auto-detect by key)
    LLM_PROVIDER: str = "auto"

    # NVIDIA NIM
    NVIDIA_API_KEY: str = ""
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    NVIDIA_MODEL: str = "minimaxai/minimax-m2.7"

    # Google Gemini
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-flash-latest"

    # OpenAI
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"

    # LLM behaviour
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_FLOWS_PER_BATCH: int = 10

    # ── System Behaviour ──────────────────────────────────────────────────────
    ENABLE_METRICS: bool = True
    # Safe default: no real firewall / SMTP actions until user opts in
    SIMULATION_MODE: bool = True
    LOG_LEVEL: str = "INFO"
    DB_PATH: str = "data/incidents.db"

    # ── LLM Budget ────────────────────────────────────────────────────────────
    BUDGET_TOKENS_PER_MINUTE: int = 50_000
    BUDGET_MAX_LLM_CALLS_PER_MINUTE: int = 20

    # ── SMTP / Email ──────────────────────────────────────────────────────────
    SMTP_SERVER: str = "smtp-relay.brevo.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""

    # ── Slack ─────────────────────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = ""

    # ── Infrastructure ────────────────────────────────────────────────────────
    REDIS_URL: str = ""
    KAFKA_BOOTSTRAP_SERVERS: str = ""

    # ── Threat Intelligence APIs ──────────────────────────────────────────────
    # All optional — system works without them; free-tier keys unlock enrichment
    ABUSEIPDB_API_KEY: str = ""      # abuseipdb.com — 1 000 checks/day free
    VIRUSTOTAL_API_KEY: str = ""     # virustotal.com — 500 lookups/day free
    SHODAN_API_KEY: str = ""         # shodan.io — community API

    # ── Bool coercion ─────────────────────────────────────────────────────────
    # Treat empty-string env vars as the field default (True for ENABLE_METRICS,
    # True for SIMULATION_MODE) so a bare `ENABLE_METRICS=` line in .env doesn't
    # raise a ValidationError.
    @field_validator("ENABLE_METRICS", "SIMULATION_MODE", mode="before")
    @classmethod
    def _empty_bool_to_default(cls, v: object) -> object:
        if isinstance(v, str) and v.strip() == "":
            return True  # empty env var → use field default (both default to True)
        return v


# ---------------------------------------------------------------------------
# Singleton — import this everywhere
# ---------------------------------------------------------------------------
settings = Settings()
