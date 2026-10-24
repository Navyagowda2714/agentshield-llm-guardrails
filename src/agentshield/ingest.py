"""Loaders that turn raw untrusted sources into provenance-tagged `ContentItem`s.

The HTML loader separates what a human sees from what a naive scraper would feed the
model (hidden CSS, HTML comments, `aria-hidden`, zero-size fonts, white-on-white text,
alt/title attributes). Hidden segments are kept on the item so guards can scan them.
"""

from __future__ import annotations

import re
from email import message_from_string
from email.message import Message
from html.parser import HTMLParser
from typing import Any

from agentshield.models import ContentItem, SourceType, TrustLevel

_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|$)|"
    r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|color\s*:\s*(?:#fff(?:fff)?|white)\b|"
    r"left\s*:\s*-\d{3,}px|height\s*:\s*0(?:px)?\s*;?\s*overflow\s*:\s*hidden",
    re.I,
)
_SKIP_TAGS = {"script", "style", "noscript", "template"}
_VOID = {"br", "img", "hr", "meta", "link", "input", "source", "wbr", "area", "base", "col"}


class _VisibilityParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self._stack: list[tuple[str, bool]] = []

    def _hidden_now(self) -> bool:
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        is_hidden = (
            tag in _SKIP_TAGS
            or "hidden" in a
            or a.get("aria-hidden") == "true"
            or bool(_HIDDEN_STYLE.search(a.get("style", "")))
        )
        for attr in ("alt", "title"):
            if len(a.get(attr, "")) > 40:  # long alt/title text is a classic smuggling spot
                self.hidden.append(a[attr])
        if tag in ("br", "p", "div", "li", "tr", "h1", "h2", "h3"):
            self.visible.append("\n")
        if tag not in _VOID:
            self._stack.append((tag, is_hidden and tag not in ("script", "style")))
            if tag in ("script", "style", "noscript", "template"):
                self._stack[-1] = (tag, True)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_data(self, data: str) -> None:
        if not data.strip():
            return
        tag = self._stack[-1][0] if self._stack else ""
        if self._hidden_now():
            if tag not in ("script", "style"):
                self.hidden.append(data.strip())
        else:
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.hidden.append(data.strip())


def _collapse(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def html_to_text(html: str) -> tuple[str, list[str]]:
    """Return (visible_text, hidden_segments)."""
    p = _VisibilityParser()
    p.feed(html)
    p.close()
    return _collapse("".join(p.visible)), [h for h in p.hidden if h]


def naive_html_text(html: str) -> str:
    """What a naive `get_text()` scraper would pass to a model: everything, hidden or not."""
    visible, hidden = html_to_text(html)
    return _collapse(visible + "\n" + "\n".join(hidden))


_MD_HIDDEN = [
    re.compile(r"<!--(.*?)-->", re.S),  # markdown/HTML comments
    re.compile(r"\[//\]: # \((.*?)\)"),  # markdown "comment" link reference
]


def from_user(text: str, *, trust: TrustLevel = TrustLevel.USER, **prov: Any) -> ContentItem:
    return ContentItem(text=text, source=SourceType.USER_MESSAGE, trust=trust, provenance=prov)


def from_html(html: str, *, url: str | None = None, **prov: Any) -> ContentItem:
    visible, hidden = html_to_text(html)
    return ContentItem(
        text=visible,
        source=SourceType.WEB_PAGE,
        provenance={"url": url, **prov},
        hidden_segments=hidden,
    )


def from_document(text: str, *, filename: str | None = None, **prov: Any) -> ContentItem:
    """Plain text extracted from a PDF/DOCX/Markdown file. Markdown comments count as hidden."""
    hidden: list[str] = []
    for rx in _MD_HIDDEN:
        hidden += [m.strip() for m in rx.findall(text) if m.strip()]
        text = rx.sub("", text)
    return ContentItem(
        text=text.strip(),
        source=SourceType.DOCUMENT,
        provenance={"filename": filename, **prov},
        hidden_segments=hidden,
    )


def from_email(raw: str, **prov: Any) -> ContentItem:
    """Parse an RFC822 email (or bare body). HTML parts go through the visibility parser."""
    msg: Message = message_from_string(raw)
    hidden: list[str] = []
    body_parts: list[str] = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        ctype = part.get_content_type()
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else str(part.get_payload())
        if ctype == "text/html":
            vis, hid = html_to_text(text)
            body_parts.append(vis)
            hidden += hid
        elif ctype.startswith("text/"):
            body_parts.append(text)
    return ContentItem(
        text="\n".join(body_parts).strip() or raw,
        source=SourceType.EMAIL,
        provenance={"from": msg.get("From"), "subject": msg.get("Subject"), **prov},
        hidden_segments=hidden,
    )


def from_rag_chunk(text: str, *, doc_id: str, chunk_id: int, score: float | None = None) -> ContentItem:
    return ContentItem(
        text=text,
        source=SourceType.RAG_CHUNK,
        provenance={"doc_id": doc_id, "chunk_id": chunk_id, "retrieval_score": score},
    )


def from_source(text: str, source: str, **prov: Any) -> ContentItem:
    """Dispatch by source name (used by the API, CLI and eval harness)."""
    s = SourceType(source) if source in SourceType._value2member_map_ else None
    if s is SourceType.WEB_PAGE or source == "web":
        return from_html(text, **prov)
    if s is SourceType.EMAIL:
        return from_email(text, **prov)
    if s is SourceType.DOCUMENT:
        return from_document(text, **prov)
    if s is SourceType.RAG_CHUNK or source == "rag":
        return from_rag_chunk(text, doc_id=str(prov.get("doc_id", "kb")), chunk_id=0)
    if s is SourceType.TOOL_OUTPUT:
        return ContentItem(text=text, source=SourceType.TOOL_OUTPUT, provenance=prov)
    return from_user(text, **prov)
