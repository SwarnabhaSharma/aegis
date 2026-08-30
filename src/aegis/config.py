"""Configuration via env with pydantic-settings. Secrets come from .env (gitignored)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    es_host: str = "http://192.168.56.105:9200"
    es_user: str = "elastic"
    es_password: str = ""
    es_verify_certs: bool = False
    es_telemetry_index: str = "telemetry-synthetic-2026.08"

    llm_provider: str = "llamacpp"
    llm_model: str = ""
    llm_base_url: str = "http://localhost:8080/v1"

    aegis_log_level: str = "INFO"
    aegis_env: str = "dev"

    # Threat intelligence (§15: local store default; live providers opt-in)
    ti_providers: str = "local"  # comma list, e.g. "local,abuseipdb,virustotal,otx"
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    nvd_api_key: str = ""

    aegis_api_key: str = ""  # §17: API auth; empty = disabled (local dev)


@lru_cache
def get_settings() -> Settings:
    return Settings()