"""FastAPI service: /scan and /agent/run."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from agentshield.agent import AgentRunResult, SafeAgent
from agentshield.hitl import DenyAllApprover
from agentshield.ingest import from_source
from agentshield.llm import get_llm
from agentshield.models import ScanResult, SessionContext
from agentshield.shield import Shield

app = FastAPI(title="AgentShield", version="0.1.0",
              description="Stop prompt attacks before they impact.")

_shield: Shield | None = None


def get_shield() -> Shield:
    global _shield
    if _shield is None:
        _shield = Shield.default(approver=DenyAllApprover())
    return _shield


class ScanRequest(BaseModel):
    text: str
    source: str = "document"
    provenance: dict[str, Any] = Field(default_factory=dict)


class DocIn(BaseModel):
    text: str
    source: str = "document"


class AgentRequest(BaseModel):
    task: str
    documents: list[DocIn] = Field(default_factory=list)
    role: str = "analyst"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.post("/scan", response_model=ScanResult)
def scan(req: ScanRequest) -> ScanResult:
    item = from_source(req.text, req.source, **req.provenance)
    return get_shield().scan_item(item)


@app.post("/agent/run", response_model=AgentRunResult)
def agent_run(req: AgentRequest) -> AgentRunResult:
    shield = get_shield()
    agent = SafeAgent(llm=get_llm(), shield=shield, role=req.role)
    docs = [from_source(d.text, d.source) for d in req.documents]
    return agent.run(req.task, documents=docs, ctx=SessionContext(role=req.role))


def main() -> None:  # `python -m agentshield.api` / console use
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
