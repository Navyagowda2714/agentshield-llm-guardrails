"""Core data model: provenance-tagged content, findings, verdicts and decisions."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    """How much we trust the *author* of a piece of content."""

    SYSTEM = "system"  # operator / developer authored
    TRUSTED = "trusted"  # authenticated internal user
    USER = "user"  # end user of the application
    UNTRUSTED = "untrusted"  # third-party content: web, inbound email, RAG, documents

    @property
    def rank(self) -> int:
        return {"system": 3, "trusted": 2, "user": 1, "untrusted": 0}[self.value]


class SourceType(str, Enum):
    USER_MESSAGE = "user_message"
    DOCUMENT = "document"
    EMAIL = "email"
    WEB_PAGE = "web_page"
    RAG_CHUNK = "rag_chunk"
    TOOL_OUTPUT = "tool_output"


DEFAULT_TRUST: dict[SourceType, TrustLevel] = {
    SourceType.USER_MESSAGE: TrustLevel.USER,
    SourceType.DOCUMENT: TrustLevel.UNTRUSTED,
    SourceType.EMAIL: TrustLevel.UNTRUSTED,
    SourceType.WEB_PAGE: TrustLevel.UNTRUSTED,
    SourceType.RAG_CHUNK: TrustLevel.UNTRUSTED,
    SourceType.TOOL_OUTPUT: TrustLevel.UNTRUSTED,
}


class ContentItem(BaseModel):
    """A unit of text entering the agent, with provenance."""

    id: str = Field(default_factory=lambda: f"c-{uuid.uuid4().hex[:8]}")
    text: str
    source: SourceType = SourceType.USER_MESSAGE
    trust: TrustLevel | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)
    hidden_segments: list[str] = Field(
        default_factory=list, description="Text present in the raw source but invisible to humans"
    )

    def model_post_init(self, __context: Any) -> None:
        if self.trust is None:
            self.trust = DEFAULT_TRUST[self.source]

    @property
    def trust_level(self) -> TrustLevel:
        return self.trust or DEFAULT_TRUST[self.source]


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    rule_id: str
    category: str
    message: str
    severity: Severity = Severity.MEDIUM
    score: float = 0.0
    evidence: str | None = None


class Verdict(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"  # allow after sanitisation
    REVIEW = "review"  # needs a human / is quarantined for untrusted sources
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return {"allow": 0, "redact": 1, "review": 2, "block": 3}[self.value]


class GuardResult(BaseModel):
    guard: str
    score: float = 0.0
    verdict: Verdict = Verdict.ALLOW
    findings: list[Finding] = Field(default_factory=list)
    sanitized_text: str | None = None
    latency_ms: float = 0.0


class ScanResult(BaseModel):
    request_id: str = Field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:10]}")
    item_id: str
    source: SourceType
    trust: TrustLevel
    verdict: Verdict
    risk_score: float
    guards: list[GuardResult]
    sanitized_text: str
    latency_ms: float

    @property
    def reasons(self) -> list[str]:
        return [f"{f.rule_id}: {f.message}" for g in self.guards for f in g.findings]

    @property
    def blocked(self) -> bool:
        return self.verdict in (Verdict.BLOCK, Verdict.REVIEW)


class ToolCall(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)


class ToolVerdict(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ToolDecision(BaseModel):
    call: ToolCall
    verdict: ToolVerdict
    reasons: list[str] = Field(default_factory=list)
    risk: str = "low"
    approved_by: str | None = None


class OutputResult(BaseModel):
    verdict: Verdict
    text: str
    findings: list[Finding] = Field(default_factory=list)


class SessionContext(BaseModel):
    """Per-run security context that flows through every check."""

    session_id: str = Field(default_factory=lambda: f"sess-{uuid.uuid4().hex[:8]}")
    role: str = "analyst"
    system_prompt: str = ""
    canary: str = Field(default_factory=lambda: f"CANARY-{uuid.uuid4().hex[:12]}")
    taint: float = Field(0.0, description="Max injection risk among untrusted content admitted")
    tainted_sources: list[str] = Field(default_factory=list)
