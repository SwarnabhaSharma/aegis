"""LLM integration (Phase 3). Swappable provider; llama.cpp OpenAI-compat.

AI is a reasoning component, never an authority (ADR-005). Every call here
returns plain data; policy/executor/verifier remain deterministic.

Fail-safe (R-001): structured-output attempt -> parse fallback -> retry-once
-> deterministic degrade. A degraded agent never produces autonomous actions.
"""

import ast
import json
import re
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
        last_raw = ""
        for attempt in (1, 2):  # retry-once
            try:
                raw = self._call(system, user, temperature)
                last_raw = raw
                data = json.loads(_extract_json(raw))
                if not isinstance(data, dict):
                    raise ValueError("expected JSON object")
                return LLMResult(ok=True, data=data, raw=raw)
            except (LLMError, json.JSONDecodeError, ValueError):
                if attempt == 2:
                    return self._degrade(system, user, last_raw)
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

    def _degrade(self, system: str, user: str, raw: str = "") -> LLMResult:
        # Deterministic fallback: never fabricate. Signal degrade; caller decides.
        detail = raw.strip().replace("\n", " ")[:200]
        return LLMResult(
            ok=False,
            data={},
            raw=raw,
            degraded=True,
            error=f"LLM unavailable or unparseable; deterministic degrade; last raw: {detail!r}",
        )


def _balanced_braces(text: str) -> str | None:
    """Slice text from first '{' to its matching '}' (quote-aware)."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    quote = None
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if ch == "\\":
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _extract_json(raw: str) -> str:
    """Strip think blocks/fences; decode FIRST object (models batch calls).

    Fallbacks beyond strict JSON:
    - concatenated tool-call objects -> raw_decode takes the first
    - Python-literal dicts (single quotes) -> ast.literal_eval
    """
    if not raw:
        raise ValueError("empty LLM response")
    if "<think>" in raw:
        raw = raw.split("</think>", 1)[-1]
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`").removeprefix("json").strip()
    start = raw.find("{")
    if start == -1:
        raise ValueError("no JSON object in response")
    candidate = raw[start:]
    try:
        obj, _ = json.JSONDecoder().raw_decode(candidate)
        return json.dumps(obj)
    except json.JSONDecodeError:
        pass
    # ponytail: odd-quote-count literals (contractions) break balancing;
    # fall back to whole candidate and let contraction repair fix pairing.
    sliced = _balanced_braces(candidate) or candidate
    try:
        return json.dumps(ast.literal_eval(sliced))
    except (ValueError, SyntaxError, MemoryError):
        pass
    # contraction repair: 'doesn't' breaks literal_eval; use typographic '
    repaired = re.sub(r"([A-Za-z])'([A-Za-z])",
                      lambda m: m.group(1) + "\u2019" + m.group(2), sliced)
    if repaired != sliced:
        try:
            return json.dumps(ast.literal_eval(repaired))
        except (ValueError, SyntaxError, MemoryError):
            pass
    raise ValueError("no parseable JSON object in response")