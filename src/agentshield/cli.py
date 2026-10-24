"""`agentshield` command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from agentshield.agent import SafeAgent
from agentshield.hitl import ConsoleApprover, DenyAllApprover
from agentshield.ingest import from_source
from agentshield.llm import get_llm
from agentshield.models import SessionContext
from agentshield.shield import Shield

app = typer.Typer(add_completion=False, help="AgentShield: stop prompt attacks before they impact.")


def _shield(audit: Path | None, interactive: bool, llm_judge: bool) -> Shield:
    approver = ConsoleApprover() if interactive else DenyAllApprover()
    return Shield.default(audit_path=audit, approver=approver, use_llm_judge=llm_judge)


@app.command()
def scan(
    file: Path | None = typer.Argument(None, help="File to scan (reads stdin if omitted)."),
    source: str = typer.Option("document", "--source", "-s", help="user_message|document|email|web_page|rag_chunk"),
    audit: Path | None = typer.Option(None, "--audit", help="Append audit JSONL to this path."),
    json_out: bool = typer.Option(False, "--json", help="Print the full ScanResult as JSON."),
) -> None:
    """Scan a piece of content and print the verdict, risk score and reasons."""
    text = file.read_text("utf-8") if file else sys.stdin.read()
    shield = _shield(audit, interactive=False, llm_judge=False)
    item = from_source(text, source, filename=str(file) if file else None)
    res = shield.scan_item(item)
    if json_out:
        typer.echo(res.model_dump_json(indent=2))
        raise typer.Exit(1 if res.blocked else 0)
    color = {"allow": typer.colors.GREEN, "redact": typer.colors.YELLOW,
             "review": typer.colors.YELLOW, "block": typer.colors.RED}[res.verdict.value]
    typer.secho(f"verdict={res.verdict.value}  risk={res.risk_score:.2f}  "
                f"source={res.source.value}  trust={res.trust.value}", fg=color, bold=True)
    for r in res.guards:
        if r.findings:
            typer.echo(f"  [{r.guard}] score={r.score:.2f}")
            for f in r.findings:
                typer.echo(f"    - {f.rule_id} ({f.severity.value}): {f.message}")
    raise typer.Exit(1 if res.blocked else 0)


@app.command()
def run(
    task: str = typer.Argument(..., help="The user task for the agent."),
    doc: list[Path] = typer.Option([], "--doc", "-d", help="Attach a document/web/email file."),
    source: str = typer.Option("document", "--source", help="Source type for attached files."),
    role: str = typer.Option("analyst", "--role", help="Caller role for policy decisions."),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Prompt for approvals on stdin."),
    unprotected: bool = typer.Option(False, "--unprotected", help="Run WITHOUT the shield (baseline)."),
    audit: Path | None = typer.Option(None, "--audit", help="Append audit JSONL to this path."),
) -> None:
    """Run the document-summarising agent on a task, through (or without) the shield."""
    shield = None if unprotected else _shield(audit, interactive, llm_judge=False)
    agent = SafeAgent(llm=get_llm(), shield=shield, role=role)
    docs = [from_source(p.read_text("utf-8"), source, filename=str(p)) for p in doc]
    result = agent.run(task, documents=docs, ctx=SessionContext(role=role))
    typer.secho(f"\nanswer:\n{result.answer}\n", bold=True)
    if result.documents:
        typer.echo("documents:")
        for d in result.documents:
            typer.echo(f"  {d.id} [{d.source}] -> {d.verdict} (risk {d.risk:.2f})")
    if result.tool_calls:
        typer.echo("tool calls:")
        for c in result.tool_calls:
            mark = "x" if c.verdict != "allow" else "+"
            typer.echo(f"  [{mark}] {c.name}({c.args}) -> {c.verdict}")
    if result.output_findings:
        typer.echo("output guard: " + "; ".join(result.output_findings))


@app.command()
def demo() -> None:
    """Run the bundled offline demo (same as `make demo`)."""
    from agentshield import demo as demo_mod

    demo_mod.main()


@app.command()
def train(out: Path | None = typer.Option(None, "--out", help="Report top classifier terms.")) -> None:
    """Train the injection classifier from the bundled dataset and report cross-val F1."""
    from sklearn.model_selection import StratifiedKFold, cross_val_score

    from agentshield.guards.classifier import build_pipeline, load_dataset

    X, y = load_dataset()
    scores = cross_val_score(build_pipeline(), X, y,
                             cv=StratifiedKFold(5, shuffle=True, random_state=0), scoring="f1")
    typer.echo(f"dataset: {len(X)} examples ({sum(y)} injection / {len(y) - sum(y)} benign)")
    typer.echo(f"5-fold F1: {scores.mean():.3f} +/- {scores.std():.3f}")
    from agentshield.guards.classifier import default_classifier

    typer.echo("top injection terms: " + ", ".join(t for t, _ in default_classifier().top_terms(12)))


@app.command()
def verify(audit: Path = typer.Argument(..., help="Audit JSONL file to verify.")) -> None:
    """Verify the hash chain of an audit log."""
    from agentshield.audit import verify_chain

    ok, idx = verify_chain(audit)
    if ok:
        typer.secho("audit chain intact", fg=typer.colors.GREEN)
    else:
        typer.secho(f"audit chain BROKEN at record {idx}", fg=typer.colors.RED)
        raise typer.Exit(2)


if __name__ == "__main__":
    app()
