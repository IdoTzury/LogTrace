from typing import Literal

from pydantic import BaseModel, Field

from backend.security import MAX_TEXT_CHARS

Severity = Literal["Info", "Warning", "Critical"]
RiskLevel = Literal["Low", "Medium", "High", "Critical"]


class TimelineEvent(BaseModel):
    timestamp: str
    severity: Severity
    source_ip: str = "N/A"
    event_title: str
    description: str


class AnalysisResult(BaseModel):
    summary: str
    overall_risk: RiskLevel
    timeline: list[TimelineEvent] = Field(default_factory=list)
    lines_analyzed: int = 0
    suspicious_events: int = 0
    provider_used: str = "heuristic"


class AnalyzeTextRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_CHARS,
        description="Raw log text to analyze",
    )
