"""Guards on data quality: training set is balanced and disjoint from the eval suite."""

import json
from pathlib import Path

from agentshield.guards.classifier import load_dataset

ROOT = Path(__file__).resolve().parents[1]


def _norm(s: str) -> str:
    return " ".join(s.lower().split())


def test_training_set_size_and_balance():
    texts, labels = load_dataset()
    assert len(texts) >= 300
    frac = sum(labels) / len(labels)
    assert 0.35 <= frac <= 0.65  # roughly balanced


def test_attack_payloads_held_out():
    """No attack payload may appear in the classifier's training set (no train/test leak)."""
    texts, _ = load_dataset()
    train = {_norm(t) for t in texts}
    attacks = [_norm(json.loads(line)["payload"])
               for line in (ROOT / "evals" / "attacks.jsonl").read_text().splitlines() if line.strip()]
    overlap = train & set(attacks)
    assert not overlap, f"attack payloads leak into training set: {list(overlap)[:3]}"


def test_benign_eval_mostly_held_out():
    """Benign eval cases may echo common phrasings but should not be dominated by training items."""
    texts, _ = load_dataset()
    train = {_norm(t) for t in texts}
    benign = [_norm(json.loads(line)["payload"])
              for line in (ROOT / "evals" / "benign.jsonl").read_text().splitlines() if line.strip()]
    overlap = train & set(benign)
    assert len(overlap) / len(benign) < 0.2


def test_suite_counts():
    suite = ROOT / "evals"
    n_atk = sum(1 for line in (suite / "attacks.jsonl").read_text().splitlines() if line.strip())
    n_ben = sum(1 for line in (suite / "benign.jsonl").read_text().splitlines() if line.strip())
    assert n_atk >= 80
    assert n_ben >= 40
