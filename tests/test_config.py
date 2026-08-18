"""Phase 0 — config defaults and boot smoke test."""

import subprocess

from aegis.config import Settings


def test_defaults_without_env_file():
    s = Settings(_env_file=None)
    assert s.es_host == "http://192.168.56.105:9200"
    assert s.llm_provider == "llamacpp"
    assert s.llm_base_url == "http://localhost:8080/v1"
    assert s.aegis_env == "dev"


def test_secrets_gitignored():
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    gitignore = (root / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", "elk_stack.txt", "*.key", "*.pem"):
        assert pattern in gitignore
    # .env may exist locally (integration creds) but git must ignore it
    if (root / ".env").exists():
        out = subprocess.run(
            ["git", "check-ignore", ".env"], cwd=root, capture_output=True, text=True
        )
        assert out.returncode == 0 and ".env" in out.stdout, ".env must be git-ignored"