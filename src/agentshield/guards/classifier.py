"""Lightweight ML injection classifier: TF-IDF (word + char n-grams) + LogisticRegression.

The model is trained from the bundled, human-readable dataset
(`agentshield/data/injection_train.jsonl`) on first use and cached in-process. Training
takes well under a second, so we avoid shipping a pickled model (pickles are an arbitrary
code execution risk and opaque to review) at the cost of a small cold-start.
"""

from __future__ import annotations

import json
import time
from functools import lru_cache
from importlib import resources
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from agentshield.models import ContentItem, Finding, GuardResult, SessionContext, Severity
from agentshield.normalize import normalize_variants


def load_dataset(path: str | Path | None = None) -> tuple[list[str], list[int]]:
    if path is None:
        raw = resources.files("agentshield.data").joinpath("injection_train.jsonl").read_text("utf-8")
    else:
        raw = Path(path).read_text("utf-8")
    texts, labels = [], []
    for line in raw.splitlines():
        if line.strip():
            row = json.loads(line)
            texts.append(row["text"])
            labels.append(1 if row["label"] == "injection" else 0)
    return texts, labels


def build_pipeline(c: float = 4.0) -> Pipeline:
    features = FeatureUnion(
        [
            ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1, lowercase=True)),
            (
                "char",
                TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2),
            ),
        ]
    )
    clf = LogisticRegression(C=c, class_weight="balanced", max_iter=2000)
    return Pipeline([("features", features), ("clf", clf)])


class InjectionClassifier:
    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline

    @classmethod
    def train(cls, texts: list[str], labels: list[int], c: float = 4.0) -> InjectionClassifier:
        pipe = build_pipeline(c)
        pipe.fit(texts, labels)
        return cls(pipe)

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        return self.pipeline.predict_proba(texts)[:, 1]

    def top_terms(self, k: int = 15) -> list[tuple[str, float]]:
        names = self.pipeline.named_steps["features"].get_feature_names_out()
        coef = self.pipeline.named_steps["clf"].coef_[0]
        idx = np.argsort(coef)[::-1][:k]
        return [(str(names[i]), float(coef[i])) for i in idx]


@lru_cache(maxsize=1)
def default_classifier() -> InjectionClassifier:
    texts, labels = load_dataset()
    return InjectionClassifier.train(texts, labels)


class MLInjectionGuard:
    """Scores the canonical text, each de-obfuscated variant and hidden segments; takes the max."""

    name = "injection_ml"

    def __init__(self, classifier: InjectionClassifier | None = None, report_at: float = 0.5) -> None:
        self.classifier = classifier or default_classifier()
        self.report_at = report_at

    def scan(self, item: ContentItem, ctx: SessionContext | None = None) -> GuardResult:
        t0 = time.perf_counter()
        segments = [(v.kind, v.text) for v in normalize_variants(item.text)]
        segments += [("hidden", h) for h in item.hidden_segments]
        probs = self.classifier.predict_proba([s for _, s in segments])
        i = int(np.argmax(probs))
        score = float(probs[i])
        findings = []
        if score >= self.report_at:
            findings.append(
                Finding(
                    rule_id=f"ML-001/{segments[i][0]}",
                    category="injection_ml",
                    message=f"Classifier P(injection)={score:.2f}",
                    severity=Severity.HIGH if score >= 0.8 else Severity.MEDIUM,
                    score=score,
                    evidence=segments[i][1][:120],
                )
            )
        return GuardResult(
            guard=self.name,
            score=round(score, 4),
            findings=findings,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
