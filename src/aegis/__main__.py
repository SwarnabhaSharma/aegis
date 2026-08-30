"""Aegis entry point. `python -m aegis` starts the server."""

import uvicorn

from aegis.config import get_settings
from aegis.logging_config import setup_logging


def main() -> None:
    settings = get_settings()
    setup_logging(settings.aegis_log_level)
    print(
        f"Aegis {settings.aegis_env} — LLM backend: "
        f"{settings.llm_provider} ({settings.llm_base_url})"
    )
    uvicorn.run("aegis.api:app", host="0.0.0.0", port=8000,
                reload=settings.aegis_env == "dev")


if __name__ == "__main__":
    main()
