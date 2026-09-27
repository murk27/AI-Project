"""Local data classification engine.

Classifies text payloads as 'Safe' or 'Sensitive/Proprietary' entirely
offline (spaCy + Presidio, no external API calls). Run with:

    uvicorn classifier.main:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI

from classifier.engine import DSPMClassifier
from classifier.models import ClassifyRequest, ClassifyResponse, EntityHit

app = FastAPI(title="DSPM Local Classification Engine", version="0.1.0")

_classifier: DSPMClassifier | None = None


@app.on_event("startup")
def _load_model() -> None:
    global _classifier
    _classifier = DSPMClassifier()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_loaded": _classifier is not None}


@app.post("/classify", response_model=ClassifyResponse)
def classify(payload: ClassifyRequest) -> ClassifyResponse:
    assert _classifier is not None, "classifier not initialized"
    result = _classifier.classify(payload.text_content)
    return ClassifyResponse(
        classification=result.classification,
        confidence_score=result.confidence_score,
        trigger=result.trigger,
        entity_type=result.entity_type,
        entities=[EntityHit(**vars(e)) for e in result.entities],
    )
