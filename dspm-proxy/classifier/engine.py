"""Classification engine: wraps a local Presidio AnalyzerEngine (spaCy-backed,
fully offline) with a scoring policy tuned for a low false-positive rate.

Policy
------
1. Any single "high precision" hit (checksum/format-validated PII, or a
   specific secret pattern like an AWS key / GitHub token / PEM header)
   is enough to flag the payload on its own.
2. "Supporting" hits (generic NER like PERSON, loose contextual matches)
   never trigger a flag alone — only when at least two of them corroborate
   each other, and even then at a capped confidence.
3. Everything else is Safe.

This mirrors how real DLP engines keep precision high: deterministic,
validated patterns do the heavy lifting; NER/context only adds weight.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from classifier.recognizers import (
    ALL_CUSTOM_RECOGNIZERS,
    HIGH_PRECISION_ENTITIES,
    SUPPORTING_ENTITIES,
)

HIGH_PRECISION_THRESHOLD = 0.55
SUPPORTING_THRESHOLD = 0.3
MIN_SUPPORTING_CORROBORATION = 2
SUPPORTING_CONFIDENCE_CAP = 0.65

NLP_CONFIGURATION = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}


@dataclass
class Entity:
    entity_type: str
    text: str
    score: float
    start: int
    end: int


@dataclass
class ClassificationResult:
    classification: str  # "Safe" | "Sensitive/Proprietary"
    confidence_score: float
    trigger: str | None
    entity_type: str | None
    entities: list[Entity] = field(default_factory=list)


class DSPMClassifier:
    def __init__(self) -> None:
        nlp_engine = NlpEngineProvider(nlp_configuration=NLP_CONFIGURATION).create_engine()

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=["en"])
        for recognizer in ALL_CUSTOM_RECOGNIZERS:
            registry.add_recognizer(recognizer)

        self._analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine, supported_languages=["en"])

    def classify(self, text: str) -> ClassificationResult:
        if not text or not text.strip():
            return ClassificationResult("Safe", 0.0, None, None, [])

        results = self._analyzer.analyze(text=text, language="en")

        high_hits = [
            r for r in results if r.entity_type in HIGH_PRECISION_ENTITIES and r.score >= HIGH_PRECISION_THRESHOLD
        ]
        supporting_hits = [
            r for r in results if r.entity_type in SUPPORTING_ENTITIES and r.score >= SUPPORTING_THRESHOLD
        ]

        all_entities = [
            Entity(r.entity_type, text[r.start : r.end], round(r.score, 3), r.start, r.end)
            for r in sorted(results, key=lambda r: r.score, reverse=True)
        ]

        if high_hits:
            top = max(high_hits, key=lambda r: r.score)
            return ClassificationResult(
                classification="Sensitive/Proprietary",
                confidence_score=round(top.score, 3),
                trigger=text[top.start : top.end],
                entity_type=top.entity_type,
                entities=all_entities,
            )

        if len(supporting_hits) >= MIN_SUPPORTING_CORROBORATION:
            top = max(supporting_hits, key=lambda r: r.score)
            confidence = min(SUPPORTING_CONFIDENCE_CAP, sum(r.score for r in supporting_hits) / len(supporting_hits))
            return ClassificationResult(
                classification="Sensitive/Proprietary",
                confidence_score=round(confidence, 3),
                trigger=text[top.start : top.end],
                entity_type=top.entity_type,
                entities=all_entities,
            )

        return ClassificationResult(
            classification="Safe",
            confidence_score=round(1 - max((r.score for r in results), default=0.0), 3),
            trigger=None,
            entity_type=None,
            entities=all_entities,
        )
