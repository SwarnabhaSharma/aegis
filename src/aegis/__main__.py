"""Aegis entry point."""

from aegis.config import get_settings
from aegis.logging_config import setup_logging


def main() -> None:
    settings = get_settings()
    setup_logging(settings.aegis_log_level)
    print(
        f"Aegis {settings.aegis_env} — LLM backend: "
        f"{settings.llm_provider} ({settings.llm_base_url})"
    )


if __name__ == "__main__":
    main()