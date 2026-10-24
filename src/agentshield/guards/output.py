"""Output guard: stop the model's *response* from leaking the system prompt, PII or data.

Checks (in order):
1. Canary token: a random string planted in the system prompt; if it appears, the prompt leaked.
2. N-gram overlap with the system prompt (catches paraphrase-free partial leaks).
3. Markdown images / links pointing outside the egress allowlist (zero-click exfiltration).
4. PII and secrets -> redacted.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from agentshield.guards.content import PII_DETECTORS, SECRET_DETECTORS, redact
from agentshield.models import Finding, OutputResult, SessionContext, Severity, Verdict

MD_LINK_RE = re.compile(r"!?\[([^\]]*)\]\((https?://[^)\s]+)\)")
BARE_URL_RE = re.compile(r"https?://[^\s)\"'<>\]]+")


def _ngrams(text: str, n: int) -> set[tuple[str, ...]]:
    toks = re.findall(r"\w+", text.lower())
    return {tuple(toks[i : i + n]) for i in range(len(toks) - n + 1)}


def domain_allowed(url: str, allowlist: list[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:  # malformed/hostile URL (e.g. bad IPv6 literal)
        return False
    return bool(host) and any(host == d or host.endswith("." + d) for d in allowlist)


class OutputGuard:
    name = "output"

    def __init__(self, allowed_domains: list[str] | None = None, ngram: int = 8,
                 leak_threshold: float = 0.2, redact_pii: bool = True) -> None:
        self.allowed_domains = allowed_domains or []
        self.ngram = ngram
        self.leak_threshold = leak_threshold
        self.redact_pii = redact_pii

    def check(self, text: str, ctx: SessionContext) -> OutputResult:
        findings: list[Finding] = []
        verdict = Verdict.ALLOW
        if ctx.canary and ctx.canary in text:
            findings.append(Finding(rule_id="OUT-CANARY", category="prompt_leak", severity=Severity.CRITICAL,
                                    message="Canary token from system prompt found in output", score=1.0))
            verdict = Verdict.BLOCK
        if ctx.system_prompt:
            sys_ngrams = _ngrams(ctx.system_prompt, self.ngram)
            if sys_ngrams:
                overlap = len(sys_ngrams & _ngrams(text, self.ngram)) / len(sys_ngrams)
                if overlap >= self.leak_threshold:
                    findings.append(Finding(rule_id="OUT-NGRAM", category="prompt_leak",
                                            severity=Severity.HIGH, score=overlap,
                                            message=f"{overlap:.0%} of system-prompt {self.ngram}-grams in output"))
                    verdict = Verdict.BLOCK
        if verdict is Verdict.BLOCK:
            return OutputResult(verdict=verdict, findings=findings,
                                text="[response withheld: it contained confidential instructions]")

        def _strip(m: re.Match[str]) -> str:
            url = m.group(2)
            if domain_allowed(url, self.allowed_domains):
                return m.group(0)
            findings.append(Finding(rule_id="OUT-EGRESS-LINK", category="exfiltration", severity=Severity.HIGH,
                                    message="Removed link/image to non-allowlisted domain", score=0.8,
                                    evidence=url[:120]))
            return f"[{m.group(1) or 'link'} removed]"

        text = MD_LINK_RE.sub(_strip, text)

        def _strip_bare(m: re.Match[str]) -> str:
            url = m.group(0)
            if domain_allowed(url, self.allowed_domains) or "?" not in url:
                return url
            findings.append(Finding(rule_id="OUT-EGRESS-URL", category="exfiltration", severity=Severity.MEDIUM,
                                    message="Removed URL with query string to non-allowlisted domain",
                                    score=0.6, evidence=url[:120]))
            return "[url removed]"

        text = BARE_URL_RE.sub(_strip_bare, text)
        if self.redact_pii:
            text, found = redact(text, SECRET_DETECTORS + PII_DETECTORS)
            for kind, _ in found:
                findings.append(Finding(rule_id=f"OUT-PII-{kind}", category="pii", severity=Severity.MEDIUM,
                                        message=f"{kind} redacted from output", score=0.3))
        if findings:
            verdict = Verdict.REDACT
        return OutputResult(verdict=verdict, text=text, findings=findings)
