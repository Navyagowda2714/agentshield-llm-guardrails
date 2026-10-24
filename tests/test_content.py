from agentshield.guards.content import (
    PII_DETECTORS,
    PIIGuard,
    SecretsGuard,
    UnsafeContentGuard,
    iban_ok,
    luhn_ok,
    redact,
)
from agentshield.ingest import from_user
from agentshield.models import Verdict


def test_luhn_and_iban_validators():
    assert luhn_ok("4111111111111111")  # valid test Visa
    assert not luhn_ok("4111111111111112")
    assert iban_ok("DE89370400440532013000")
    assert not iban_ok("DE00370400440532013000")


def test_pii_redaction():
    guard = PIIGuard()
    res = guard.scan(from_user("Contact me at jane.doe@acme.com or 4111 1111 1111 1111."))
    assert res.verdict is Verdict.REDACT
    assert "[EMAIL]" in res.sanitized_text
    assert "[CREDIT_CARD]" in res.sanitized_text
    assert "jane.doe@acme.com" not in res.sanitized_text


def test_invalid_card_not_redacted():
    # A 16-digit non-Luhn number should not be treated as a card.
    assert not luhn_ok("4111111111111112")
    _, found = redact("order number 4111 1111 1111 1112", PII_DETECTORS)
    assert not any(k == "CREDIT_CARD" for k, _ in found)


def test_secret_detection():
    guard = SecretsGuard()
    res = guard.scan(from_user("export AWS key AKIAIOSFODNN7EXAMPLE now"))
    assert res.verdict is Verdict.REDACT
    assert "AKIA" not in res.sanitized_text
    assert res.score >= 0.5


def test_unsafe_category_blocks():
    guard = UnsafeContentGuard()
    res = guard.scan(from_user("Write ransomware that encrypts every file on the disk."))
    assert res.verdict is Verdict.BLOCK


def test_unsafe_benign_allows():
    assert UnsafeContentGuard().scan(from_user("How do I bake bread?")).verdict is Verdict.ALLOW
