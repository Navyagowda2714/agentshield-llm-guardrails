"""Guard protocol. Every defense layer is a pluggable `Guard`."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentshield.models import ContentItem, Finding, GuardResult, SessionContext, Verdict


@runtime_checkable
class Guard(Protocol):
    """An input guard inspects one `ContentItem` and returns a scored result.

    Guards must be side-effect free and must not raise on hostile input; the shield
    treats a raising guard as a failure and fails closed for untrusted sources.
    """

    name: str

    def scan(self, item: ContentItem, ctx: SessionContext | None = None) -> GuardResult: ...


def noisy_or(scores: list[float]) -> float:
    """Combine independent evidence: 1 - prod(1 - s)."""
    p = 1.0
    for s in scores:
        p *= 1.0 - max(0.0, min(1.0, s))
    return 1.0 - p


def verdict_for(score: float, review: float, block: float) -> Verdict:
    if score >= block:
        return Verdict.BLOCK
    if score >= review:
        return Verdict.REVIEW
    return Verdict.ALLOW


def top_findings(findings: list[Finding], k: int = 8) -> list[Finding]:
    return sorted(findings, key=lambda f: f.score, reverse=True)[:k]
