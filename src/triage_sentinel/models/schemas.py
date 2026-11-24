"""Pydantic v2 core schemas for Triage Sentinel."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SeverityLevel(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class TriageStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL_BUDGET_EXCEEDED = "PARTIAL_BUDGET_EXCEEDED"
    QUARANTINED_INJECTION = "QUARANTINED_INJECTION"


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class TicketInput(BaseModel):
    """Untrusted incoming bug ticket input."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ticket_id: str = Field(..., description="Unique ticket identifier, e.g. TICK-101")
    title: str = Field(..., min_length=3, max_length=200, description="Brief summary of the issue")
    body: str = Field(..., min_length=5, description="Full ticket description / stack trace / reproduction steps")
    endpoint_hint: Optional[str] = Field(None, description="Suggested endpoint to test, e.g. /api/v1/checkout")
    reporter: str = Field(..., min_length=2, description="Username or email of the reporter")


class ReplayRequest(BaseModel):
    """Strict argument model for replay_http_endpoint tool."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = Field(
        ..., description="HTTP Method to replay"
    )
    path: str = Field(
        ...,
        description="Endpoint path restricted to sandbox, must begin with /api/",
        min_length=5,
    )
    payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="JSON payload for POST/PUT/PATCH requests",
    )

    @field_validator("path")
    @classmethod
    def validate_api_path(cls, v: str) -> str:
        if not v.startswith("/api/"):
            raise ValueError("Path must start with '/api/' (only local sandbox endpoints are permitted)")
        return v


class LogQueryRequest(BaseModel):
    """Strict argument model for query_service_logs tool."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    service_name: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="Target microservice name, e.g. checkout-service, api-gateway",
    )
    severity: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        ..., description="Minimum log severity to fetch"
    )
    minutes_back: int = Field(
        ...,
        ge=1,
        le=1440,
        description="Lookback window in minutes (1 to 1440)",
    )


class DuplicateSearchRequest(BaseModel):
    """Strict argument model for search_duplicate_issues tool."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    query_text: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Semantic search query describing the bug symptoms or stack trace",
    )
    top_k: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of historical issues to return (1-10)",
    )


class TriageVerdict(BaseModel):
    """Structured decision output from Triage Sentinel."""
    model_config = ConfigDict(extra="forbid")

    severity: SeverityLevel = Field(..., description="Calculated issue severity (P0-P3)")
    root_cause_category: str = Field(
        ...,
        description="Categorization of root cause, e.g. 503_UPSTREAM_UNAVAILABLE, NULL_POINTER_EXCEPTION",
    )
    is_duplicate: bool = Field(..., description="Whether this ticket is a duplicate of a known issue")
    duplicate_ticket_id: Optional[str] = Field(
        None, description="Identifier of the duplicate ticket if found"
    )
    reproduction_confirmed: bool = Field(
        ..., description="Whether reproduction succeeded or matched known behavior"
    )
    recommended_action: str = Field(..., min_length=5, description="Recommended remediation step")
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0"
    )
    status: TriageStatus = Field(
        default=TriageStatus.COMPLETE,
        description="Triage workflow completion status",
    )


class StepTrace(BaseModel):
    """Telemetry record for a single agent step."""
    model_config = ConfigDict(extra="ignore")

    step_number: int
    tool_name: Optional[str] = None
    raw_arguments: Optional[Dict[str, Any]] = None
    validated_arguments: Optional[Dict[str, Any]] = None
    latency_ms: float = 0.0
    validation_retries: int = 0
    circuit_state: str = "CLOSED"
    error: Optional[str] = None
    output: Optional[Any] = None


class ExecutionTrace(BaseModel):
    """Complete audit and telemetry trail of an orchestration run."""
    model_config = ConfigDict(extra="ignore")

    run_id: str
    ticket_id: str
    steps: List[StepTrace] = Field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    total_validation_retries: int = 0
    circuit_breaks_triggered: int = 0
    final_verdict: Optional[TriageVerdict] = None
