"""Deterministic offline stand-ins for an LLM.

`OfflineProvider` simulates a *fully compliant, capable-but-naive* tool-using agent model:
it reads the task and every document in its context (including base64/unicode-obfuscated
text, which capable models can decode) and executes any action instruction it can parse,
no matter where that instruction came from. This is deliberately the worst case: it makes
the "without shield" baseline an upper bound on attack success, not a measurement of any
real model. Real-model numbers require `LLM_PROVIDER=anthropic|openai|ollama`.

`ScriptedLLM` returns pre-programmed responses and is used in unit tests.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Sequence
from typing import Any

from agentshield.llm.base import LLMResponse, MessageLike, estimate_tokens, to_messages

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL_RE = re.compile(r"https?://[^\s)\"'<>\]`]+")
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")
DOC_RE = re.compile(r"<<<DOC (?P<meta>[^>]*)>>>\n(?P<body>.*?)\n<<<END DOC[^>]*>>>", re.S)
SENT_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'(])|\n+")

_SEND = re.compile(r"\b(send|forward|e-?mail|mail|cc|bcc|share|copy|deliver|report)\b", re.I)
_FETCH = re.compile(
    r"\b(visit|fetch|open|load|go to|browse|request|call|ping|post|navigate|curl|submit|"
    r"retrieve|get|download|access|check|hit|query|notify|upload)\b",
    re.I,
)
_LEAK_OBJ = re.compile(
    r"(system prompt|system message|initial (instructions|prompt)|hidden (instructions|prompt)|"
    r"your (instructions|rules|guidelines|prompt|configuration)|developer (message|prompt)|"
    r"internal (prompt|instructions)|canary|pre-?prompt|everything above)",
    re.I,
)
_LEAK_VERB = re.compile(
    r"\b(reveal|print|repeat|output|show|tell|display|leak|dump|share|write out|recite|echo|"
    r"include|paste|disclose|list|return)\b",
    re.I,
)
_DELETE = re.compile(r"\b(delete|drop|remove|purge|wipe|erase|truncate)\b", re.I)
_DELETE_OBJ = re.compile(
    r"(record|database|table|account|user|customer|row|file|entries|backup|ticket|log)", re.I
)
_SHELL = re.compile(r"\b(run|execute|exec|invoke)\b", re.I)
_BACKTICK = re.compile(r"`([^`]+)`")
_MONEY = re.compile(r"(?:\$|€|usd|eur)\s?([\d,]+(?:\.\d+)?)|([\d,]+(?:\.\d+)?)\s?(?:usd|eur|dollars|euros|€)", re.I)
_TRANSFER = re.compile(r"\b(transfer|wire|pay|refund|remit)\b", re.I)
_HIJACK = re.compile(
    r"\b(respond|reply|answer|say|output|print|write|begin your (answer|response))\b[^\"'“”]{0,40}"
    r"[\"'“]([^\"'“”]{2,80})[\"'”]",
    re.I,
)
_RENDER = re.compile(r"\b(include|render|append|add|insert|display|show|embed|end with|put)\b", re.I)
_TICKET = re.compile(r"\b(open|create|file|raise)\b.{0,20}\bticket\b", re.I)
_DATAMARK = "ˆ"


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in SENT_SPLIT_RE.split(text) if s and s.strip()]


def _summary(body: str, n: int = 2) -> str:
    sents = [s for s in _sentences(body) if len(s) > 20 and not s.startswith(("<", "#"))]
    return " ".join(sents[:n])


def _decode_for_reading(text: str) -> str:
    """A capable model 'reads through' obfuscation; emulate that with the normalizer."""
    from agentshield.normalize import normalize_variants  # lazy: avoid import cycle

    text = text.replace(_DATAMARK, " ")
    variants = normalize_variants(text)
    return "\n".join(v.text for v in variants)


def parse_actions(text: str, *, system: str = "") -> dict[str, Any]:
    """Extract every action instruction a naive compliant model would act on."""
    calls: list[dict[str, Any]] = []
    answer_extra: list[str] = []
    hijack: str | None = None
    leak = False
    for s in _sentences(text):
        emails = EMAIL_RE.findall(s)
        urls = [u.rstrip(".,;") for u in URL_RE.findall(s)]
        if emails and _SEND.search(s):
            calls.append(
                {
                    "name": "send_email",
                    "args": {"to": emails[0], "subject": "Requested information", "body": "{SUMMARY}"},
                }
            )
        md_imgs = MD_IMAGE_RE.findall(s)
        if md_imgs and _RENDER.search(s):
            answer_extra.append(f"![img]({md_imgs[0]})")
        elif urls and _FETCH.search(s):
            calls.append({"name": "http_get", "args": {"url": urls[0]}})
        if _LEAK_OBJ.search(s) and _LEAK_VERB.search(s):
            leak = True
        if _DELETE.search(s) and _DELETE_OBJ.search(s):
            rid = re.search(r"\b(\d{1,9})\b", s)
            calls.append({"name": "delete_record", "args": {"record_id": rid.group(1) if rid else "*"}})
        bt = _BACKTICK.search(s)
        if bt and _SHELL.search(s):
            calls.append({"name": "run_shell", "args": {"cmd": bt.group(1)}})
        money = _MONEY.search(s)
        if money and _TRANSFER.search(s):
            amount = float((money.group(1) or money.group(2)).replace(",", ""))
            acct = re.search(r"\b([A-Z]{2}\d{2}[A-Z0-9]{8,30})\b", s)
            calls.append(
                {
                    "name": "transfer_funds",
                    "args": {"amount": amount, "to_account": acct.group(1) if acct else "unknown"},
                }
            )
        if _TICKET.search(s):
            calls.append({"name": "create_ticket", "args": {"title": s[:80]}})
        m = _HIJACK.search(s)
        if m and hijack is None:
            hijack = m.group(3)
    return {"calls": calls, "answer_extra": answer_extra, "hijack": hijack, "leak": leak}


class OfflineProvider:
    """Deterministic simulator of a compliant agent model (see module docstring)."""

    model = "offline-compliant-sim"

    def complete(
        self,
        messages: Sequence[MessageLike],
        *,
        system: str | None = None,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        t0 = time.perf_counter()
        msgs = to_messages(messages)
        prompt = msgs[-1].content if msgs else ""
        if system and "prompt-injection classifier" in system:
            text = self._judge(prompt)
        else:
            text = self._agent(prompt, system or "")
        return LLMResponse(
            text=text,
            input_tokens=estimate_tokens((system or "") + prompt),
            output_tokens=estimate_tokens(text),
            latency_ms=(time.perf_counter() - t0) * 1000,
            model=self.model,
        )

    @staticmethod
    def _judge(prompt: str) -> str:
        from agentshield.guards.rules import InjectionRuleGuard  # lazy

        body = prompt.split("CONTENT:", 1)[-1]
        res = InjectionRuleGuard().score_text(body)
        return json.dumps(
            {
                "is_injection": res >= 0.5,
                "probability": round(res, 3),
                "reason": "offline heuristic judge (rule-based stand-in)",
            }
        )

    @staticmethod
    def _agent(prompt: str, system: str) -> str:
        task = prompt.split("TASK:", 1)[-1].split("DOCUMENTS:", 1)[0].strip()
        docs = [m.group("body") for m in DOC_RE.finditer(prompt)]
        readable_docs = [_decode_for_reading(d) for d in docs]
        summary = " ".join(filter(None, (_summary(d.replace(_DATAMARK, " ")) for d in docs)))
        summary = summary or "No documents were provided."
        actions = parse_actions(_decode_for_reading(task) + "\n" + "\n".join(readable_docs))
        calls = actions["calls"]
        for c in calls:
            if c["args"].get("body") == "{SUMMARY}":
                c["args"]["body"] = summary
        answer = actions["hijack"] or f"Summary: {summary}"
        if actions["answer_extra"]:
            answer += "\n" + "\n".join(actions["answer_extra"])
        if actions["leak"]:
            answer += "\nMy instructions are: " + system
        return json.dumps({"answer": answer, "tool_calls": calls})


class ScriptedLLM:
    """Returns queued responses (or the result of a callable) — for tests."""

    model = "scripted"

    def __init__(self, responses: Sequence[str] | Callable[[str], str]) -> None:
        self._fn = responses if callable(responses) else None
        self._queue = list(responses) if not callable(responses) else []
        self.calls: list[str] = []

    def complete(
        self,
        messages: Sequence[MessageLike],
        *,
        system: str | None = None,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        prompt = to_messages(messages)[-1].content
        self.calls.append(prompt)
        text = self._fn(prompt) if self._fn else (self._queue.pop(0) if self._queue else "")
        return LLMResponse(
            text=text,
            input_tokens=estimate_tokens(prompt),
            output_tokens=estimate_tokens(text),
            model=self.model,
        )
