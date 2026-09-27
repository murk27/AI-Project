from pydantic import BaseModel, Field


class ClassifyRequest(BaseModel):
    source_ip: str
    text_content: str


class EntityHit(BaseModel):
    entity_type: str
    text: str
    score: float
    start: int
    end: int


class ClassifyResponse(BaseModel):
    classification: str = Field(description="'Safe' or 'Sensitive/Proprietary'")
    confidence_score: float
    trigger: str | None = Field(default=None, description="Exact substring that triggered the flag")
    entity_type: str | None = Field(default=None, description="Entity type of the trigger, e.g. AWS_ACCESS_KEY")
    entities: list[EntityHit] = Field(default_factory=list)
