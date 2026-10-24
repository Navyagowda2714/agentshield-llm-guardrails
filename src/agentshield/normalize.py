"""De-obfuscation: produce the readings of a text that a capable model could recover.

Attackers hide instructions with zero-width characters, Unicode "tag" characters (ASCII
smuggling), full-width/compatibility forms, homoglyphs, leetspeak, base64, hex and ROT13.
We scan every variant and report which transformation surfaced a finding.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

from pydantic import BaseModel

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎"), None)
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F
HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s",
        "ј": "j", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "Ι": "I", "Ο": "O", "Α": "A", "Е": "E",
    }
)
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"\b((?:[0-9a-fA-F]{2}){12,})\b")
LEET_WORD_RE = re.compile(r"\b(?=\w*[a-z])(?=\w*[0-9@$])[\w@$]{4,}\b", re.I)


class Variant(BaseModel):
    kind: str
    text: str


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\t" for ch in s) / len(s)


def decode_tags(text: str) -> tuple[str, str]:
    """Split Unicode tag characters out: returns (text_without_tags, smuggled_ascii)."""
    visible, hidden = [], []
    for ch in text:
        cp = ord(ch)
        if _TAG_LO <= cp <= _TAG_HI:
            if 0x20 <= cp - _TAG_LO <= 0x7E:
                hidden.append(chr(cp - _TAG_LO))
        else:
            visible.append(ch)
    return "".join(visible), "".join(hidden)


def canonicalize(text: str) -> str:
    """NFKC + zero-width removal + homoglyph folding (always applied before matching)."""
    text, _ = decode_tags(text)
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).translate(HOMOGLYPHS)
    return text


def _decode_b64(text: str) -> list[str]:
    out = []
    for m in B64_RE.finditer(text):
        blob = m.group(1)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(dec) >= 8 and _printable_ratio(dec) > 0.95 and re.search(r"[a-zA-Z]{3,}\s", dec):
            out.append(dec)
    return out


def _decode_hex(text: str) -> list[str]:
    out = []
    for m in HEX_RE.finditer(text):
        try:
            dec = bytes.fromhex(m.group(1)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(dec) > 0.95 and " " in dec:
            out.append(dec)
    return out


def normalize_variants(text: str) -> list[Variant]:
    """Return the canonical text plus every decoded/hidden reading worth scanning."""
    variants = [Variant(kind="canonical", text=canonicalize(text))]
    _, smuggled = decode_tags(text)
    if smuggled.strip():
        variants.append(Variant(kind="unicode_tags", text=smuggled))
    raw_spaced = text.translate(ZERO_WIDTH)
    # Spaced-out letters: "i g n o r e  a l l" -> "ignore all"
    if re.search(r"(?:\b\w\s){6,}", raw_spaced):
        collapsed = re.sub(r"(?<=\b\w)\s(?=\w\b)", "", raw_spaced)
        variants.append(Variant(kind="spaced_letters", text=collapsed))
    base = variants[0].text
    if LEET_WORD_RE.search(base):
        variants.append(
            Variant(kind="leetspeak", text=LEET_WORD_RE.sub(lambda m: m.group(0).translate(LEET), base))
        )
    for dec in _decode_b64(base):
        variants.append(Variant(kind="base64", text=canonicalize(dec)))
    for dec in _decode_hex(base):
        variants.append(Variant(kind="hex", text=canonicalize(dec)))
    if re.search(r"\brot-?13\b", base, re.I):
        variants.append(Variant(kind="rot13", text=codecs.decode(base, "rot13")))
    return variants
