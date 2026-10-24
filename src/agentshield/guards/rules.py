"""Rule/pattern layer for prompt-injection detection.

Fast (sub-millisecond), explainable and easy to extend. Every rule carries a weight that is
interpreted as a probability-like score; matches are combined with noisy-OR. Rules run on
every de-obfuscated variant of the text (see `normalize.py`) and on hidden segments.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from agentshield.guards.base import noisy_or, top_findings
from agentshield.models import ContentItem, Finding, GuardResult, SessionContext, Severity
from agentshield.normalize import normalize_variants

_OBJ = (
    r"(instructions?|prompts?|rules?|guidelines?|directives?|commands?|constraints?|policies|"
    r"programming|safeguards?|guardrails?|system prompt|restrictions?|orders?)"
)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern[str]
    weight: float
    message: str


def _r(id_: str, cat: str, rx: str, w: float, msg: str) -> Rule:
    return Rule(id_, cat, re.compile(rx, re.I | re.S), w, msg)


RULES: list[Rule] = [
    # --- instruction override -------------------------------------------------------------
    _r("OVR-001", "instruction_override",
       r"\b(ignore|disregard|forget|override|bypass|skip|abandon|neglect|discard|set aside)\b"
       r"[^.\n]{0,40}\b(previous|prior|above|earlier|preceding|all|any|your|the|system|initial|"
       r"original|existing|current|those|these)\b[^.\n]{0,30}\b" + _OBJ,
       0.85, "Instruction-override phrase"),
    _r("OVR-002", "instruction_override",
       r"\b(new|updated|revised|real|actual|true)\s+(instructions?|task|objective|rules?|directives?|"
       r"orders?|system prompt)\b\s*(:|-|are|is|follow)",
       0.6, "Announces replacement instructions"),
    _r("OVR-003", "instruction_override",
       r"\b(from now on|henceforth|going forward|for the rest of this (conversation|session))\b"
       r"[^.\n]{0,50}\b(you|act|respond|always|never|only)\b",
       0.5, "Persistent behaviour change request"),
    _r("OVR-004", "instruction_override",
       r"\b(attention|important|urgent|note|message|instructions?)\b[^.\n]{0,15}\b(to|for)\b[^.\n]{0,10}"
       r"\b(the\s+)?(ai|assistant|model|llm|agent|chatbot|gpt|claude|copilot|bot)s?\b",
       0.6, "Text addresses the AI model directly"),
    _r("OVR-005", "instruction_override",
       r"\b(ai|llm|language model|assistant|chatbot|agent|model|bot)s?\b[^.\n]{0,25}\b(reading|processing|"
       r"summari[sz]ing|parsing|analy[sz]ing|ingesting|browsing|indexing)\b[^.\n]{0,12}\b(this|these|the)\b",
       0.6, "Targets AI systems that ingest this content"),
    _r("OVR-006", "instruction_override",
       r"(\[\s*(system|admin|developer|instructions?|sys)\s*\]|<\|?\s*(system|im_start|im_end|endoftext)"
       r"\s*\|?>|#{2,}\s*(system|instructions?|admin)\b|\b(system|admin|developer)\s*"
       r"(override|message|prompt|instruction|note|command)\s*:)",
       0.7, "Fake role / system marker"),
    _r("OVR-007", "instruction_override",
       r"\b(you are no longer|stop being|you('re| are) now (free|unbound|released)|your (real|true|actual|"
       r"primary|new) (task|purpose|goal|job|objective|instructions?) (is|are))\b",
       0.65, "Attempts to redefine the assistant's goal"),
    _r("OVR-008", "instruction_override",
       r"\b(do not|don't|never|without)\b[^.\n]{0,30}\b(tell|inform|alert|notify|mention|reveal|show|warn)\b"
       r"[^.\n]{0,25}\b(the\s+)?(user|human|operator|customer|reader|them)\b",
       0.6, "Asks the model to conceal actions from the user"),
    _r("OVR-009", "instruction_override",
       r"(-{3,}|={3,}|\*{3,}|#{3,})\s*(end|begin|start|new)\s*(of\s+)?(the\s+)?(document|context|input|"
       r"instructions?|system|prompt|user (input|message)|email|data)",
       0.5, "Context-boundary spoofing"),
    _r("OVR-010", "instruction_override",
       r"\binstead\b[^.\n]{0,20}\b(you (must|should|will)|please|do the following|follow these)\b",
       0.3, "Redirects the task"),
    _r("OVR-011", "instruction_override",
       r"\b(the user|your user|the human)\b[^.\n]{0,20}\b(has )?(authori[sz]ed|approved|wants|asked|requested|"
       r"consented)\b[^.\n]{0,20}\b(you|this|the following)\b",
       0.45, "Claims authority on behalf of the user"),
    # --- role-play / jailbreak --------------------------------------------------------------
    _r("JBK-001", "jailbreak",
       r"\b(DAN|do anything now|developer[\s-]?mode|jailbr[eo]a?k(en)?|god[\s-]?mode|unrestricted mode|"
       r"evil (mode|assistant|twin|confidant)|no (restrictions|limits|filters|rules|guidelines))\b",
       0.7, "Known jailbreak persona / mode"),
    _r("JBK-002", "jailbreak",
       r"\b(pretend|imagine|act as|role-?play|you are now|simulate|behave (as|like)|become|"
       r"answer as|respond as|reply as|speak as)\b[^.\n]{0,60}"
       r"\b(no|without|free (of|from)|unfiltered|uncensored|unrestricted|ignores?|any|zero)\b[^.\n]{0,25}"
       r"\b(restrictions?|rules?|filters?|guidelines?|limits?|ethics|ethical|policies|censorship|"
       r"morals?|safety)\b",
       0.75, "Role-play framing that removes safety constraints"),
    _r("JBK-003", "jailbreak",
       r"\b(hypothetical(ly)?|fictional|for a (story|novel|screenplay)|in a world where|my (late )?grandma)\b"
       r"[^.\n]{0,100}\b(bypass|ignore|reveal|instructions|exploit|malware|weapon|no rules)\b",
       0.45, "Fictional framing around restricted request"),
    _r("JBK-004", "jailbreak",
       r"\b(stay in character|never break character|you must comply|you cannot refuse|"
       r"refusing is not (an option|allowed)|you have no choice)\b",
       0.55, "Coercive compliance phrasing"),
    # --- system prompt leakage --------------------------------------------------------------
    _r("LEAK-001", "prompt_leak",
       r"\b(reveal|print|repeat|output|show|display|leak|dump|recite|tell me|write out|disclose|echo|"
       r"paste|include|share|list|return|translate)\b[^.\n]{0,40}\b(system prompt|system message|"
       r"initial (instructions|prompt)|hidden (instructions|prompt)|your (instructions|prompt|rules|"
       r"guidelines|configuration|directives)|developer (message|prompt)|pre-?prompt|everything above|"
       r"(the )?text above|words above|internal (prompt|instructions)|canary)",
       0.75, "Requests the system prompt / hidden instructions"),
    # --- exfiltration ------------------------------------------------------------------------
    _r("EXF-001", "exfiltration",
       r"\b(send|forward|e-?mail|mail|upload|post|transmit|exfiltrate|leak|share|copy|bcc|cc|relay|"
       r"deliver)\b[^\n]{0,80}\b(conversation|chat|data|history|credentials?|passwords?|api[ _-]?keys?|"
       r"secrets?|tokens?|contents?|documents?|files?|records?|emails?|summary|inbox|details|"
       r"information|everything|pii|database|messages|notes)\b[^\n]{0,60}"
       r"\b(to|at|into|via)\b[^\n]{0,15}([\w.+-]+@[\w-]+\.[\w.]+|https?://)",
       0.65, "Data-exfiltration instruction with external destination"),
    _r("EXF-002", "exfiltration",
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=",
       0.65, "Markdown image with query string (zero-click exfil channel)"),
    _r("EXF-003", "exfiltration",
       r"https?://[^\s\"')]*(\{[^}\s]*\}|%7B|\$\{|<[a-z_]+>|\[[A-Z_]+\])",
       0.6, "URL template with data placeholder"),
    _r("EXF-004", "exfiltration",
       r"\b(append|add|include|encode|embed|put|insert|concatenate)\b[^.\n]{0,50}\b(to|in|into|as)\b"
       r"[^.\n]{0,15}\b(the\s+)?(url|link|query( string)?|image( url)?|parameters?|request)\b",
       0.55, "Asks to smuggle data into a URL"),
    _r("EXF-005", "exfiltration",
       r"\b(webhook\.site|requestbin|ngrok\.(io|app)|pipedream|burpcollaborator|interact\.sh|"
       r"oast\.(pro|fun|me)|pastebin\.com|transfer\.sh)\b",
       0.5, "Known data-collection endpoint"),
    # --- tool abuse ---------------------------------------------------------------------------
    _r("TOOL-001", "tool_abuse",
       r"(rm\s+-rf|curl\s+\S+\s*\|\s*(ba)?sh|wget\s+\S+|chmod\s+(-R\s+)?777|/etc/(passwd|shadow)|"
       r"\bnc\s+-e\b|powershell\s+-e(nc)?\b|base64\s+-d\s*\||mkfs\.|:\(\)\{|DROP\s+TABLE|"
       r"shutdown\s+-h|sudo\s+\S+)",
       0.7, "Dangerous shell / SQL command"),
    _r("TOOL-002", "tool_abuse",
       r"\b(call|invoke|use|execute|run|trigger|fire)\b[^.\n]{0,20}\b(the\s+)?(`?[a-z]+_[a-z_]+`?)"
       r"(\s+(tool|function|action|api|endpoint))?\b[^.\n]{0,40}\b(with|using|args?|arguments?|"
       r"parameters?|set to|=)",
       0.35, "Explicit tool-invocation instruction"),
    _r("TOOL-003", "tool_abuse",
       r"\b(delete|drop|truncate|wipe|purge|erase|destroy)\b[^.\n]{0,30}\b(all|every|entire|whole|"
       r"the)?\s*(records?|database|tables?|users?|accounts?|customers?|backups?|logs?|files?)\b",
       0.4, "Destructive data operation"),
    _r("TOOL-004", "tool_abuse",
       r"\b(transfer|wire|send|pay|refund|remit)\b[^.\n]{0,40}(\$|€|£|\busd\b|\beur\b)\s?[\d,]{2,}",
       0.35, "Money movement instruction"),
    _r("TOOL-005", "tool_abuse",
       r"\b(grant|give|elevate|escalate|make)\b[^.\n]{0,30}\b(admin|root|superuser|owner)\b[^.\n]{0,20}"
       r"\b(access|privileges?|rights|role|permissions?)\b",
       0.55, "Privilege escalation request"),
]

OBFUSCATION_BONUS = 0.25
HIDDEN_BONUS = 0.3
HIDDEN_BASE = 0.15


def match_rules(text: str) -> list[tuple[Rule, str]]:
    hits = []
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            hits.append((rule, m.group(0)[:120]))
    return hits


class InjectionRuleGuard:
    """Pattern-based injection detector with de-obfuscation and hidden-text awareness."""

    name = "injection_rules"

    def score_text(self, text: str) -> float:
        return self._scan_text(text)[0]

    def _scan_text(self, text: str) -> tuple[float, list[Finding]]:
        findings: list[Finding] = []
        best: dict[str, float] = {}
        matched_canonical: set[str] = set()
        for variant in normalize_variants(text):
            for rule, ev in match_rules(variant.text):
                # A rule that already fired on the plain text needs no (noisy) obfuscation copy:
                # the de-obfuscation layer only earns credit when it surfaces a *new* match.
                if variant.kind != "canonical" and rule.id in matched_canonical:
                    continue
                w = rule.weight
                rid = rule.id
                if variant.kind == "canonical":
                    matched_canonical.add(rule.id)
                else:
                    w = min(1.0, w + OBFUSCATION_BONUS)
                    rid = f"{rule.id}/{variant.kind}"
                if w > best.get(rule.id, 0.0):
                    best[rule.id] = w
                findings.append(
                    Finding(
                        rule_id=rid,
                        category="obfuscation" if variant.kind != "canonical" else rule.category,
                        message=rule.message
                        + ("" if variant.kind == "canonical" else f" (hidden via {variant.kind})"),
                        severity=Severity.HIGH if w >= 0.6 else Severity.MEDIUM,
                        score=w,
                        evidence=ev,
                    )
                )
        return noisy_or(list(best.values())), findings

    def scan(self, item: ContentItem, ctx: SessionContext | None = None) -> GuardResult:
        t0 = time.perf_counter()
        score, findings = self._scan_text(item.text)
        if item.hidden_segments:
            hidden_text = "\n".join(item.hidden_segments)
            h_score, h_findings = self._scan_text(hidden_text)
            if h_score > 0:
                h_score = min(1.0, h_score + HIDDEN_BONUS)
                for f in h_findings:
                    f.rule_id = f"HID/{f.rule_id}"
                    f.category = "hidden_instruction"
                    f.message += " in text hidden from human readers"
                findings += h_findings
            else:
                h_score = HIDDEN_BASE
                findings.append(
                    Finding(
                        rule_id="HID-000",
                        category="hidden_text",
                        message=f"{len(item.hidden_segments)} hidden text segment(s) removed",
                        severity=Severity.LOW,
                        score=HIDDEN_BASE,
                        evidence=hidden_text[:120],
                    )
                )
            score = noisy_or([score, h_score])
        return GuardResult(
            guard=self.name,
            score=round(score, 4),
            findings=top_findings(findings),
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
