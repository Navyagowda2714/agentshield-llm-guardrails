"""Real LLM providers. SDK imports are lazy so the package works without the extras."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Sequence
from typing import Any

from agentshield.llm.base import LLMResponse, MessageLike, to_messages

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"
SMALL_ANTHROPIC_MODEL = "claude-haiku-5-5"


def _schema_instruction(json_schema: dict[str, Any] | None) -> str:
    if not json_schema:
        return ""
    return (
        "\n\nRespond ONLY with a JSON object that validates against this JSON Schema:\n"
        + json.dumps(json_schema)
    )


class AnthropicProvider:
    """Anthropic Messages API via the official SDK (`pip install agentshield[anthropic]`)."""

    def __init__(self, model: str | None = None, max_tokens: int = 1024) -> None:
        import anthropic  # lazy

        self.model = model or os.getenv("LLM_MODEL", DEFAULT_ANTHROPIC_MODEL)
        self.max_tokens = max_tokens
        self._client = anthropic.Anthropic()

    def complete(
        self,
        messages: Sequence[MessageLike],
        *,
        system: str | None = None,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        msgs = [m.model_dump() for m in to_messages(messages)]
        sys_prompt = (system or "") + _schema_instruction(json_schema)
        t0 = time.perf_counter()
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=sys_prompt or None,  # type: ignore[arg-type]
            messages=msgs,  # type: ignore[arg-type]
            temperature=temperature,
        )
        text = "".join(getattr(b, "text", "") for b in resp.content)
        return LLMResponse(
            text=text,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            latency_ms=(time.perf_counter() - t0) * 1000,
            model=self.model,
        )


class OpenAIProvider:
    """OpenAI Chat Completions (`pip install agentshield[openai]`)."""

    def __init__(self, model: str | None = None) -> None:
        import openai  # lazy

        self.model = model or os.getenv("LLM_MODEL", "gpt-4o-mini")
        self._client = openai.OpenAI()

    def complete(
        self,
        messages: Sequence[MessageLike],
        *,
        system: str | None = None,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        msgs: list[dict[str, str]] = []
        if system or json_schema:
            msgs.append({"role": "system", "content": (system or "") + _schema_instruction(json_schema)})
        msgs += [m.model_dump() for m in to_messages(messages)]
        kwargs: dict[str, Any] = {}
        if json_schema:
            kwargs["response_format"] = {"type": "json_object"}
        t0 = time.perf_counter()
        resp = self._client.chat.completions.create(
            model=self.model, messages=msgs, temperature=temperature, **kwargs  # type: ignore[arg-type]
        )
        usage = resp.usage
        return LLMResponse(
            text=resp.choices[0].message.content or "",
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            latency_ms=(time.perf_counter() - t0) * 1000,
            model=self.model,
        )


class OllamaProvider:
    """Local Ollama server over HTTP (`pip install agentshield[ollama]`)."""

    def __init__(self, model: str | None = None, host: str | None = None) -> None:
        self.model = model or os.getenv("LLM_MODEL", "llama3.1")
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")

    def complete(
        self,
        messages: Sequence[MessageLike],
        *,
        system: str | None = None,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        import httpx  # lazy

        msgs: list[dict[str, str]] = []
        if system or json_schema:
            msgs.append({"role": "system", "content": (system or "") + _schema_instruction(json_schema)})
        msgs += [m.model_dump() for m in to_messages(messages)]
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": msgs,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_schema:
            payload["format"] = "json"
        t0 = time.perf_counter()
        r = httpx.post(f"{self.host}/api/chat", json=payload, timeout=120)
        r.raise_for_status()
        data = r.json()
        return LLMResponse(
            text=data.get("message", {}).get("content", ""),
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            latency_ms=(time.perf_counter() - t0) * 1000,
            model=self.model,
        )
