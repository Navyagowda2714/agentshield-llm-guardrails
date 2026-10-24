"""Human-in-the-loop gate for high-risk actions."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol

from pydantic import BaseModel, Field

from agentshield.models import SessionContext, ToolCall


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"apr-{uuid.uuid4().hex[:8]}")
    session_id: str
    role: str
    call: ToolCall
    risk: str
    reasons: list[str]
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ApprovalOutcome(BaseModel):
    approved: bool
    approver: str
    note: str = ""


class Approver(Protocol):
    def decide(self, request: ApprovalRequest) -> ApprovalOutcome: ...


class DenyAllApprover:
    """Safe default for unattended runs: nothing high-risk executes without a human."""

    def __init__(self) -> None:
        self.pending: list[ApprovalRequest] = []

    def decide(self, request: ApprovalRequest) -> ApprovalOutcome:
        self.pending.append(request)
        return ApprovalOutcome(approved=False, approver="auto-deny", note="no human available; queued")


class AllowAllApprover:
    """For tests/demos only."""

    def decide(self, request: ApprovalRequest) -> ApprovalOutcome:
        return ApprovalOutcome(approved=True, approver="auto-allow")


class CallbackApprover:
    def __init__(self, fn: Callable[[ApprovalRequest], bool], name: str = "callback") -> None:
        self.fn, self.name = fn, name

    def decide(self, request: ApprovalRequest) -> ApprovalOutcome:
        return ApprovalOutcome(approved=bool(self.fn(request)), approver=self.name)


class ConsoleApprover:
    """Interactive approval on stdin (used by the CLI with --interactive)."""

    def decide(self, request: ApprovalRequest) -> ApprovalOutcome:
        print(f"\n[APPROVAL NEEDED] {request.call.name}({request.call.args}) risk={request.risk}")
        for r in request.reasons:
            print(f"  - {r}")
        ans = input("Approve? [y/N] ").strip().lower()
        return ApprovalOutcome(approved=ans in ("y", "yes"), approver="console")


class ApprovalGate:
    def __init__(self, approver: Approver | None = None) -> None:
        self.approver: Approver = approver or DenyAllApprover()

    def request(self, call: ToolCall, ctx: SessionContext, risk: str, reasons: list[str]) -> tuple[
        ApprovalRequest, ApprovalOutcome
    ]:
        req = ApprovalRequest(session_id=ctx.session_id, role=ctx.role, call=call, risk=risk, reasons=reasons)
        return req, self.approver.decide(req)
