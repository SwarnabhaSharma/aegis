"""LLM integration (Phase 3). Swappable provider; llama.cpp OpenAI-compat.

AI is a reasoning component, never an authority (ADR-005). Every call here
returns plain data; policy/executor/verifier remain deterministic.

Fail-safe (R-001): structured-output attempt -> parse fallback -> retry-once
-> deterministic degrade. A degraded agent never produces autonomous actions.
"""

import json
from dataclasses import dataclass
from typing import Any

from openai import OpenAI


@dataclass
class LLMResult:
    ok: bool
    data: dict[str, Any]
    raw: str
    degraded: bool = False
    error: str = ""


class LLMError(Exception):
    pass


class LLMClient:
    """Thin OpenAI-compat client for llama.cpp (or any /v1 server)."""

    def __init__(self, base_url: str, model: str) -> None:
        if not base_url:
            raise ValueError("llm_base_url required")
        self._model = model or "default"
        self._client = OpenAI(base_url=base_url, api_key="llama-cpp")  # llama.cpp ignores key

    def complete_json(self, system: str, user: str, temperature: float = 0.0) -> LLMResult:
        for attempt in (1, 2):  # retry-once
            try:
                raw = self._call(system, user, temperature)
                data = json.loads(_extract_json(raw))
                if not isinstance(data, dict):
                    raise ValueError("expected JSON object")
                return LLMResult(ok=True, data=data, raw=raw)
            except (LLMError, json.JSONDecodeError, ValueError):
                if attempt == 2:
                    return self._degrade(system, user)
        return self._degrade(system, user)  # unreachable, keeps linters calm

    def _call(self, system: str, user: str, temperature: float) -> str:
        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=temperature,
            )
        except Exception as e:  # server down, network, etc.
            raise LLMError(str(e)) from e
        return resp.choices[0].message.content or ""

    def _degrade(self, system: str, user: str) -> LLMResult:
        # Deterministic fallback: never fabricate. Signal degrade; caller decides.
        return LLMResult(
            ok=False,
            data={},
            raw="",
            degraded=True,
            error="LLM unavailable or unparseable; deterministic degrade",
        )


def _extract_json(raw: str) -> str:
    """Strip reasoning/<think> blocks and markdown fences; return JSON object text."""
    if not raw:
        raise ValueError("empty LLM response")
    # Ornith (and similar) emit <think>...</think> before the answer.
    if "<think>" in raw:
        raw = raw.split("</think>", 1)[-1]
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`").removeprefix("json").strip()
    # last resort: first '{' through last '}' (balanced-ish; good enough for JSON)
    start, end = raw.find("{"), raw.rfind("}")
    if start != -1 and end > start:
        raw = raw[start : end + 1]
    return raw