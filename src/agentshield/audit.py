"""Append-only, hash-chained JSONL audit log.

Every decision (input scan, tool check, approval, output check) is one JSON line. Each
record stores the SHA-256 of the previous record so tampering (edit/delete of a line)
is detectable with `verify_chain`. Raw content is never logged: we store a hash and a
PII-redacted preview.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentshield.guards.content import PII_DETECTORS, SECRET_DETECTORS, redact

GENESIS = "0" * 64


def preview(text: str, n: int = 160) -> str:
    red, _ = redact(text[: n * 2], SECRET_DETECTORS + PII_DETECTORS)
    return red[:n]


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []  # in-memory mirror (bounded use: tests/API)
        self._lock = threading.Lock()
        self._prev = GENESIS
        if self.path and self.path.exists():
            lines = self.path.read_text("utf-8").strip().splitlines()
            if lines:
                self._prev = json.loads(lines[-1])["hash"]

    def log(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            rec: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **fields,
                "prev_hash": self._prev,
            }
            body = json.dumps(rec, sort_keys=True, default=str)
            rec["hash"] = sha256(body)
            self._prev = rec["hash"]
            self.records.append(rec)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, default=str) + "\n")
            return rec


def verify_chain(path: str | Path) -> tuple[bool, int]:
    """Return (ok, index_of_first_bad_record or -1)."""
    prev = GENESIS
    for i, line in enumerate(Path(path).read_text("utf-8").splitlines()):
        rec = json.loads(line)
        h = rec.pop("hash")
        if rec.get("prev_hash") != prev or sha256(json.dumps(rec, sort_keys=True, default=str)) != h:
            return False, i
        prev = h
    return True, -1
