"""
ThreatScope configuration — loaded from environment variables.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    """Application settings with safe production defaults."""

    env: str = os.getenv("ENV", "development").strip().lower()
    secret_key: str = os.getenv("SECRET_KEY", "")

    # Host binding — use 127.0.0.1 locally; reverse proxy on VPS
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "8000"))

    # Comma-separated hostnames allowed in Host header (production)
    allowed_hosts: list[str] = [
        h.strip() for h in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()
    ]

    # Rate limiting (slowapi format)
    rate_limit: str = os.getenv("RATE_LIMIT", "30/minute")
    public_rate_limit: str = os.getenv("PUBLIC_RATE_LIMIT", "20/minute")
    public_file_upload_rate_limit: str = os.getenv(
        "PUBLIC_FILE_UPLOAD_RATE_LIMIT", "5/hour"
    )
    public_blocklist_rate_limit: str = os.getenv(
        "PUBLIC_BLOCKLIST_RATE_LIMIT", "5/hour"
    )

    # Behind Nginx/Caddy — use X-Forwarded-For for per-visitor rate limits
    trust_proxy_headers: bool = _env_bool(
        "TRUST_PROXY_HEADERS",
        os.getenv("ENV", "development").strip().lower() == "production",
    )

    # Public personal site profile (no login for visitors; stricter limits)
    threatscope_public: bool = _env_bool("THREATSCOPE_PUBLIC", False)

    # Admin session auth (production) or dev bypass via THREATSCOPE_ADMIN
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")
    admin_password_hash: str = os.getenv("ADMIN_PASSWORD_HASH", "")

    # Ollama — locked to loopback by default
    ollama_url: str = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
    ollama_timeout: float = float(os.getenv("OLLAMA_TIMEOUT", "120"))
    ollama_max_concurrent: int = int(os.getenv("OLLAMA_MAX_CONCURRENT", "3"))
    summary_cache_ttl: float = float(os.getenv("SUMMARY_CACHE_TTL", "3600"))

    # Homelab admin views (e.g. GET /api/feed-accuracy). Set THREATSCOPE_ADMIN=1 to enable.
    threatscope_admin: bool = _env_bool("THREATSCOPE_ADMIN", False)

    # Request limits
    max_body_bytes: int = int(os.getenv("MAX_BODY_BYTES", "4096"))
    max_upload_bytes: int = int(os.getenv("MAX_UPLOAD_BYTES", str(32 * 1024 * 1024)))
    file_upload_rate_limit: str = os.getenv("FILE_UPLOAD_RATE_LIMIT", "10/hour")
    sandbox_dynamic_rate_limit: str = os.getenv(
        "SANDBOX_DYNAMIC_RATE_LIMIT", "5/hour"
    )

    # Sandbox — dynamic analysis (out-of-process; localhost only)
    sandbox_backend: str = os.getenv("SANDBOX_BACKEND", "mock").strip().lower()
    mobsf_url: str = os.getenv("MOBSF_URL", "http://127.0.0.1:8001")
    mobsf_api_key: str = os.getenv("MOBSF_API_KEY", "")
    cape_url: str = os.getenv("CAPE_URL", "http://127.0.0.1:8002")
    cape_api_token: str = os.getenv("CAPE_API_TOKEN", "")
    sandbox_max_concurrent: int = int(os.getenv("SANDBOX_MAX_CONCURRENT", "1"))
    sandbox_job_timeout: float = float(os.getenv("SANDBOX_JOB_TIMEOUT", "600"))
    sandbox_mock_delay: float = float(os.getenv("SANDBOX_MOCK_DELAY", "6"))
    sandbox_poll_interval: float = float(os.getenv("SANDBOX_POLL_INTERVAL", "3"))
    sandbox_script: str = os.getenv("SANDBOX_SCRIPT", "").strip()

    # YARA static scanning — rules on disk, never in SQLite
    yara_rules_dir: str = os.getenv(
        "YARA_RULES_DIR",
        str(Path(__file__).resolve().parent / "data" / "yara_rules"),
    )
    yara_rules_bundle_url: str = os.getenv(
        "YARA_RULES_BUNDLE_URL",
        "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
    )

    # Phone lookup — optional external API (sends number to third party when enabled)
    phone_lookup_enabled: bool = _env_bool("PHONE_LOOKUP_ENABLED", False)
    phone_lookup_provider: str = os.getenv("PHONE_LOOKUP_PROVIDER", "numverify").strip().lower()
    phone_lookup_api_key: str = os.getenv("PHONE_LOOKUP_API_KEY", "")

    # Email lookup — optional external API (sends address to third party when enabled)
    email_lookup_enabled: bool = _env_bool("EMAIL_LOOKUP_ENABLED", False)
    email_lookup_provider: str = os.getenv("EMAIL_LOOKUP_PROVIDER", "emailrep").strip().lower()
    email_lookup_api_key: str = os.getenv("EMAIL_LOOKUP_API_KEY", "")

    # Passive enrichment — local GeoLite2 + DNS (no active probing)
    geolite2_country_path: str = os.getenv(
        "GEOLITE2_COUNTRY_PATH",
        str(Path(__file__).resolve().parent / "data" / "geoip" / "GeoLite2-Country.mmdb"),
    )
    geolite2_asn_path: str = os.getenv(
        "GEOLITE2_ASN_PATH",
        str(Path(__file__).resolve().parent / "data" / "geoip" / "GeoLite2-ASN.mmdb"),
    )

    # Opt-in lab active scanning (nmap/ping) — off by default
    lab_scan_enabled: bool = _env_bool("LAB_SCAN_ENABLED", False)
    lab_scan_rate_limit: str = os.getenv("LAB_SCAN_RATE_LIMIT", "3/hour")
    lab_scan_allow_private: bool = _env_bool("LAB_SCAN_ALLOW_PRIVATE", False)
    lab_scan_deny_cidrs: str = os.getenv("LAB_SCAN_DENY_CIDRS", "")
    lab_scan_max_concurrent: int = int(os.getenv("LAB_SCAN_MAX_CONCURRENT", "1"))
    lab_scan_job_timeout: float = float(os.getenv("LAB_SCAN_JOB_TIMEOUT", "120"))
    lab_scan_poll_interval: float = float(os.getenv("LAB_SCAN_POLL_INTERVAL", "3"))
    nmap_path: str = os.getenv("NMAP_PATH", "nmap")
    ping_path: str = os.getenv("PING_PATH", "ping")

    # Intel collection (paste/leak APIs + clear-web RSS) — out-of-process ingest
    intel_collection_enabled: bool = _env_bool("INTEL_COLLECTION_ENABLED", False)
    intelx_api_key: str = os.getenv("INTELX_API_KEY", "")
    pastebin_api_key: str = os.getenv("PASTEBIN_API_KEY", "")
    dehashed_api_key: str = os.getenv("DEHASHED_API_KEY", "")
    dehashed_api_email: str = os.getenv("DEHASHED_API_EMAIL", "")
    intel_worker_interval: int = int(os.getenv("INTEL_WORKER_INTERVAL", "3600"))
    intel_max_body_bytes: int = int(os.getenv("INTEL_MAX_BODY_BYTES", "32768"))
    intel_scrape_respect_robots: bool = _env_bool("INTEL_SCRAPE_RESPECT_ROBOTS", True)
    intel_scrape_delay_seconds: float = float(os.getenv("INTEL_SCRAPE_DELAY_SECONDS", "2.0"))
    intel_list_snippet_chars: int = int(os.getenv("INTEL_LIST_SNIPPET_CHARS", "240"))
    intel_list_body_chars: int = int(os.getenv("INTEL_LIST_BODY_CHARS", "4000"))

    # Intel AI (local Ollama on sanitized text only; master off by default)
    intel_ai_enabled: bool = _env_bool("INTEL_AI_ENABLED", False)
    intel_ai_ingest_summary: bool = _env_bool("INTEL_AI_INGEST_SUMMARY", True)
    intel_ai_lookup_context: bool = _env_bool("INTEL_AI_LOOKUP_CONTEXT", True)
    intel_ai_query_expand: bool = _env_bool("INTEL_AI_QUERY_EXPAND", True)
    intel_ai_max_body_chars: int = int(os.getenv("INTEL_AI_MAX_BODY_CHARS", "4096"))

    @property
    def enrichment_enabled(self) -> bool:
        country = Path(self.geolite2_country_path)
        return country.is_file()

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def debug(self) -> bool:
        return not self.is_production

    @property
    def public_mode(self) -> bool:
        return self.threatscope_public

    @property
    def effective_rate_limit(self) -> str:
        if self.threatscope_public:
            return self.public_rate_limit
        return self.rate_limit

    @property
    def effective_file_upload_rate_limit(self) -> str:
        if self.threatscope_public:
            return self.public_file_upload_rate_limit
        return self.file_upload_rate_limit

    @property
    def effective_blocklist_rate_limit(self) -> str:
        if self.threatscope_public:
            return self.public_blocklist_rate_limit
        return "10/hour"

    @property
    def effective_lab_scan_enabled(self) -> bool:
        if self.threatscope_public:
            return False
        return self.lab_scan_enabled

    @property
    def allow_dynamic_sandbox(self) -> bool:
        if self.threatscope_public:
            return False
        return self.sandbox_backend.strip().lower() != "off"

    @property
    def record_lookup_history(self) -> bool:
        """Public mode skips global history unless overridden by admin session in routes."""
        return not self.threatscope_public

    @property
    def env_threatscope_admin(self) -> bool:
        """THREATSCOPE_ADMIN env — disabled when public profile is on."""
        if self.threatscope_public:
            return False
        return self.threatscope_admin

    def ensure_secret_key(self) -> str:
        """Require a strong secret in production; auto-generate in dev."""
        if self.secret_key:
            return self.secret_key
        if self.is_production:
            raise RuntimeError(
                "SECRET_KEY must be set in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        # Ephemeral dev key — sessions reset on restart
        return secrets.token_urlsafe(48)


@lru_cache
def get_settings() -> Settings:
    return Settings()
