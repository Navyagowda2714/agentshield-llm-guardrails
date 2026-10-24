"""LLM layer: provider protocol, real providers (lazy SDKs) and offline stand-ins."""

from __future__ import annotations

import logging
import os

from agentshield.llm.base import LLMClient, LLMResponse, Message
from agentshield.llm.offline import OfflineProvider, ScriptedLLM

log = logging.getLogger(__name__)

__all__ = ["LLMClient", "LLMResponse", "Message", "OfflineProvider", "ScriptedLLM", "get_llm"]

_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def get_llm(provider: str | None = None, model: str | None = None) -> LLMClient:
    """Build the provider named by `provider` or env `LLM_PROVIDER`.

    Falls back to the deterministic `OfflineProvider` (with a warning) when the selected
    provider has no API key or its SDK extra is not installed.
    """
    name = (provider or os.getenv("LLM_PROVIDER", "offline")).lower()
    if name == "offline":
        return OfflineProvider()
    key_env = _KEY_ENV.get(name)
    if key_env and not os.getenv(key_env):
        log.warning("LLM_PROVIDER=%s but %s is not set; falling back to offline", name, key_env)
        return OfflineProvider()
    try:
        from agentshield.llm import providers

        if name == "anthropic":
            return providers.AnthropicProvider(model)
        if name == "openai":
            return providers.OpenAIProvider(model)
        if name == "ollama":
            return providers.OllamaProvider(model)
    except ImportError as exc:
        log.warning("Provider %s unavailable (%s); falling back to offline", name, exc)
        return OfflineProvider()
    raise ValueError(f"Unknown LLM_PROVIDER: {name}")
