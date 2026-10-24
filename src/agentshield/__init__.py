"""AgentShield: stop prompt attacks before they impact."""

from agentshield.agent import AgentRunResult, SafeAgent
from agentshield.ingest import from_document, from_email, from_html, from_rag_chunk, from_user
from agentshield.models import (
    ContentItem,
    ScanResult,
    SessionContext,
    SourceType,
    ToolCall,
    ToolDecision,
    ToolVerdict,
    TrustLevel,
    Verdict,
)
from agentshield.shield import InputBlocked, Shield, ToolBlocked

__version__ = "0.1.0"
__all__ = [
    "AgentRunResult",
    "ContentItem",
    "InputBlocked",
    "SafeAgent",
    "ScanResult",
    "SessionContext",
    "Shield",
    "SourceType",
    "ToolBlocked",
    "ToolCall",
    "ToolDecision",
    "ToolVerdict",
    "TrustLevel",
    "Verdict",
    "from_document",
    "from_email",
    "from_html",
    "from_rag_chunk",
    "from_user",
]
