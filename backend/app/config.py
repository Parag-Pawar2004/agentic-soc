"""Application settings.

Values come from environment variables, optionally loaded from a `.env` file at the
project root (written for you by `setup_soc.py`). Every integration is optional:
with no keys at all the platform still runs using the built-in heuristic analyst,
the local vector store and the mock (simulated) firewall.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent


def _load_dotenv() -> None:
    """Tiny .env loader (KEY=VALUE lines). Real environment variables win."""
    for candidate in (PROJECT_DIR / ".env", BACKEND_DIR / ".env"):
        if not candidate.exists():
            continue
        for raw in candidate.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            os.environ.setdefault(key, value)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool(name: str, default: bool = False) -> bool:
    value = _env(name, "")
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in _env(name, default).split(",") if item.strip()]


@dataclass
class Settings:
    # Core
    app_name: str = "Agentic SOC"
    data_dir: Path = BACKEND_DIR / "data"
    database_path: Path = BACKEND_DIR / "data" / "soc.db"
    cors_origins: list[str] = field(default_factory=list)
    demo_mode: bool = True

    # Auth
    analyst_username: str = "analyst"
    analyst_password: str = ""
    secret_key: str = ""
    ingest_api_key: str = ""
    token_ttl_hours: int = 12

    # LLM (open-weight Llama 3 family)
    llm_provider: str = "auto"  # auto | openrouter | groq | ollama | openai_compat | none
    openrouter_api_key: str = ""
    openrouter_model: str = "meta-llama/llama-3.3-70b-instruct"
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-20b"  # Groq retired its Llama 3 models in Aug 2026
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    openai_compat_url: str = ""
    openai_compat_key: str = ""
    openai_compat_model: str = ""
    llm_timeout: int = 60

    # RAG
    vector_store: str = "auto"  # auto | milvus | builtin
    milvus_uri: str = ""  # "" = auto (Milvus Lite file, or built-in store on Windows)
    milvus_token: str = ""
    embedding_backend: str = "auto"  # auto | fastembed | hash

    # Threat-intel import (files you supply; see app/intel/importer.py)
    intel_import_dir: Path = BACKEND_DIR / "data" / "intel_import"

    # SOAR / response
    firewall_provider: str = "mock"  # mock | aws_waf | script
    identity_provider: str = "mock"  # mock | okta | aws_iam
    aws_region: str = "us-east-1"
    aws_waf_ipset_name: str = ""
    aws_waf_ipset_id: str = ""
    aws_waf_scope: str = "REGIONAL"
    okta_org_url: str = ""
    okta_api_token: str = ""
    firewall_block_cmd: str = ""
    firewall_unblock_cmd: str = ""
    ip_allowlist: list[str] = field(default_factory=list)
    auto_approve: bool = False  # keep False: humans approve every change

    @property
    def llm_label(self) -> str:
        from .llm import describe_provider

        return describe_provider(self)


@lru_cache
def get_settings() -> Settings:
    _load_dotenv()
    data_dir = Path(_env("DATA_DIR", str(BACKEND_DIR / "data")))
    data_dir.mkdir(parents=True, exist_ok=True)
    return Settings(
        data_dir=data_dir,
        database_path=Path(_env("DATABASE_PATH", str(data_dir / "soc.db"))),
        cors_origins=_list("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"),
        demo_mode=_bool("DEMO_MODE", True),
        analyst_username=_env("ANALYST_USERNAME", "analyst"),
        analyst_password=_env("ANALYST_PASSWORD", ""),
        secret_key=_env("SECRET_KEY", ""),
        ingest_api_key=_env("INGEST_API_KEY", ""),
        token_ttl_hours=_int("TOKEN_TTL_HOURS", 12),
        llm_provider=_env("LLM_PROVIDER", "auto").lower(),
        openrouter_api_key=_env("OPENROUTER_API_KEY"),
        openrouter_model=_env("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct"),
        groq_api_key=_env("GROQ_API_KEY"),
        groq_model=_env("GROQ_MODEL", "openai/gpt-oss-20b"),
        ollama_url=_env("OLLAMA_URL", "http://localhost:11434").rstrip("/"),
        ollama_model=_env("OLLAMA_MODEL", "llama3.2:3b"),
        openai_compat_url=_env("OPENAI_COMPAT_URL").rstrip("/"),
        openai_compat_key=_env("OPENAI_COMPAT_KEY"),
        openai_compat_model=_env("OPENAI_COMPAT_MODEL"),
        llm_timeout=_int("LLM_TIMEOUT", 60),
        vector_store=_env("VECTOR_STORE", "auto").lower(),
        milvus_uri=_env("MILVUS_URI"),
        milvus_token=_env("MILVUS_TOKEN"),
        embedding_backend=_env("EMBEDDING_BACKEND", "auto").lower(),
        intel_import_dir=Path(_env("INTEL_IMPORT_DIR", str(data_dir / "intel_import"))),
        firewall_provider=_env("FIREWALL_PROVIDER", "mock").lower(),
        identity_provider=_env("IDENTITY_PROVIDER", "mock").lower(),
        aws_region=_env("AWS_REGION", "us-east-1"),
        aws_waf_ipset_name=_env("AWS_WAF_IPSET_NAME"),
        aws_waf_ipset_id=_env("AWS_WAF_IPSET_ID"),
        aws_waf_scope=_env("AWS_WAF_SCOPE", "REGIONAL").upper(),
        okta_org_url=_env("OKTA_ORG_URL").rstrip("/"),
        okta_api_token=_env("OKTA_API_TOKEN"),
        firewall_block_cmd=_env("FIREWALL_BLOCK_CMD"),
        firewall_unblock_cmd=_env("FIREWALL_UNBLOCK_CMD"),
        ip_allowlist=_list("IP_ALLOWLIST"),
        auto_approve=_bool("AUTO_APPROVE", False),
    )
