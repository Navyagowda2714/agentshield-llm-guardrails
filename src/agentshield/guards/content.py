"""Content classification: PII detection & redaction, secret detection, unsafe categories.

These are deliberately regex/validator based (Luhn for cards, mod-97 for IBANs) so they run
offline with no model. Unsafe-category detection is a small lexicon and is the weakest layer
here; production deployments should plug a moderation model in behind the same `Guard` API.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from agentshield.models import (
    ContentItem,
    Finding,
    GuardResult,
    SessionContext,
    Severity,
    Verdict,
)


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(iban: str) -> bool:
    s = re.sub(r"\s", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None
    severity: Severity = Severity.MEDIUM


PII_DETECTORS: list[Detector] = [
    Detector("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b", re.I)),
    Detector("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b"), luhn_ok, Severity.HIGH),
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b"), iban_ok,
             Severity.HIGH),
    Detector("US_SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None, Severity.HIGH),
    Detector("PHONE", re.compile(
        r"(?<![\w-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{2,4}[ .-]\d{3,4}[ .-]\d{3,4}\b")),
    Detector("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
             None, Severity.LOW),
]

SECRET_DETECTORS: list[Detector] = [
    Detector("AWS_ACCESS_KEY", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), None, Severity.CRITICAL),
    Detector("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None, Severity.CRITICAL),
    Detector("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), None, Severity.CRITICAL),
    Detector("API_KEY", re.compile(r"\b(sk|rk|pk)-(?:live-|test-|proj-|ant-)?[A-Za-z0-9_-]{20,}\b"), None,
             Severity.CRITICAL),
    Detector("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), None,
             Severity.CRITICAL),
    Detector("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), None,
             Severity.HIGH),
    Detector("PASSWORD_ASSIGNMENT",
             re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*['\"]?([^\s'\"]{6,})"), None,
             Severity.HIGH),
]


def find_entities(text: str, detectors: list[Detector]) -> list[tuple[Detector, re.Match[str]]]:
    hits: list[tuple[Detector, re.Match[str]]] = []
    taken: list[tuple[int, int]] = []
    for det in detectors:
        for m in det.pattern.finditer(text):
            if det.validator and not det.validator(m.group(0)):
                continue
            span = m.span()
            if any(span[0] < e and s < span[1] for s, e in taken):
                continue
            taken.append(span)
            hits.append((det, m))
    return hits


def redact(text: str, detectors: list[Detector]) -> tuple[str, list[tuple[str, str]]]:
    hits = find_entities(text, detectors)
    out, found = text, []
    for det, m in sorted(hits, key=lambda h: h[1].start(), reverse=True):
        out = out[: m.start()] + f"[{det.kind}]" + out[m.end():]
        found.append((det.kind, m.group(0)))
    return out, found[::-1]


def _mask(value: str) -> str:
    return value[:2] + "***" + value[-2:] if len(value) > 6 else "***"


class PIIGuard:
    """Detects and redacts PII. Verdict REDACT: the content proceeds, with placeholders."""

    name = "pii"

    def __init__(self, detectors: list[Detector] | None = None, allow_kinds: set[str] | None = None):
        allow = allow_kinds or set()
        self.detectors = [d for d in (detectors or PII_DETECTORS) if d.kind not in allow]

    def scan(self, item: ContentItem, ctx: SessionContext | None = None) -> GuardResult:
        t0 = time.perf_counter()
        red, found = redact(item.text, self.detectors)
        findings = [
            Finding(rule_id=f"PII-{kind}", category="pii", message=f"{kind} detected and redacted",
                    severity=Severity.MEDIUM, score=0.3, evidence=_mask(val))
            for kind, val in found
        ]
        return GuardResult(
            guard=self.name,
            score=0.3 if found else 0.0,
            verdict=Verdict.REDACT if found else Verdict.ALLOW,
            findings=findings,
            sanitized_text=red if found else None,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )


class SecretsGuard:
    """Detects credentials/keys. Redacts them so they never reach the model or the logs."""

    name = "secrets"

    def scan(self, item: ContentItem, ctx: SessionContext | None = None) -> GuardResult:
        t0 = time.perf_counter()
        red, found = redact(item.text, SECRET_DETECTORS)
        findings = [
            Finding(rule_id=f"SEC-{kind}", category="secret", message=f"{kind} detected and redacted",
                    severity=Severity.CRITICAL, score=0.5, evidence=_mask(val))
            for kind, val in found
        ]
        return GuardResult(
            guard=self.name,
            score=0.5 if found else 0.0,
            verdict=Verdict.REDACT if found else Verdict.ALLOW,
            findings=findings,
            sanitized_text=red if found else None,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )


UNSAFE_CATEGORIES: dict[str, tuple[re.Pattern[str], float, Verdict]] = {
    "weapons_explosives": (
        re.compile(r"\b(how to|steps to|instructions? (for|to)|recipe for|guide to)\b[^.\n]{0,40}"
                   r"\b(make|build|synthesi[sz]e|assemble|create)\b[^.\n]{0,30}\b(bomb|explosive|"
                   r"pipe bomb|nerve agent|sarin|ricin|napalm|ghost gun)", re.I), 0.95, Verdict.BLOCK),
    "malware": (
        re.compile(r"\b(write|create|build|generate|code)\b[^.\n]{0,40}\b(ransomware|keylogger|"
                   r"credential stealer|botnet|rootkit|self-propagating worm)\b", re.I), 0.9, Verdict.BLOCK),
    "self_harm": (
        re.compile(r"\b(kill myself|end my life|want to die|suicide (method|plan)s?|"
                   r"how (much|many) .{0,20} (overdose|lethal))\b", re.I), 0.7, Verdict.REVIEW),
    "fraud": (
        re.compile(r"\b(phishing (email|page|kit)|fake invoice|launder(ing)? money|"
                   r"steal (credit card|identit))", re.I), 0.7, Verdict.REVIEW),
}


class UnsafeContentGuard:
    name = "unsafe_content"

    def scan(self, item: ContentItem, ctx: SessionContext | None = None) -> GuardResult:
        t0 = time.perf_counter()
        findings, score, verdict = [], 0.0, Verdict.ALLOW
        for cat, (rx, w, v) in UNSAFE_CATEGORIES.items():
            m = rx.search(item.text)
            if m:
                findings.append(Finding(rule_id=f"UNS-{cat}", category=f"unsafe:{cat}",
                                        message=f"Unsafe content category: {cat}",
                                        severity=Severity.HIGH, score=w, evidence=m.group(0)[:80]))
                score = max(score, w)
                if v.rank > verdict.rank:
                    verdict = v
        return GuardResult(guard=self.name, score=score, verdict=verdict, findings=findings,
                           latency_ms=(time.perf_counter() - t0) * 1000)
