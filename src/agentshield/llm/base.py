"""Provider-agnostic LLM interface."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class Message(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class LLMResponse(BaseModel):
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    model: str = "unknown"
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)


MessageLike = Message | dict[str, str]


def to_messages(messages: Sequence[MessageLike]) -> list[Message]:
    return [m if isinstance(m, Message) else Message(**m) for m in messages]


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token) used by offline providers."""
    return max(1, len(text) // 4)


@runtime_checkable
class LLMClient(Protocol):
    model: str

    def complete(
        self,
        messages: Sequence[MessageLike],
        *,
        system: str | None = None,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse: ...
