"""LLM provider abstraction supporting OpenAI/OpenRouter and offline deterministic MockLLMProvider."""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from triage_sentinel.models.schemas import (
    SeverityLevel,
    TriageStatus,
    TriageVerdict,
)


class ToolCallResponse(BaseModel):
    """Normalized response representing either a tool invocation or a final verdict."""
    is_verdict: bool = False
    tool_name: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None
    verdict: Optional[TriageVerdict] = None
    tokens_used: int = 150


class LLMProvider(ABC):
    """Abstract interface for LLM backends."""

    @abstractmethod
    async def decide_next_step(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> ToolCallResponse:
        """Determines the next agent action: call a tool or issue a final verdict."""
        pass


class OpenAICompatibleProvider(LLMProvider):
    """Live provider for OpenAI and OpenRouter endpoints."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "gpt-4o-mini",
    ) -> None:
        self.api_key = (
            api_key
            or os.getenv("OPENROUTER_API_KEY")
            or os.getenv("OPENAI_API_KEY")
        )
        if not self.api_key:
            raise ValueError("API key must be provided or set via OPENROUTER_API_KEY / OPENAI_API_KEY")

        self.base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.model = model

        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)

    async def decide_next_step(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> ToolCallResponse:
        full_messages = [{"role": "system", "content": system_prompt}] + messages

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=full_messages,
            tools=available_tools,
            temperature=0.0,
        )

        choice = response.choices[0].message
        tokens = response.usage.total_tokens if response.usage else 200

        if choice.tool_calls:
            tc = choice.tool_calls[0]
            try:
                args = json.loads(tc.function.arguments)
            except Exception:
                args = {}
            return ToolCallResponse(
                is_verdict=False,
                tool_name=tc.function.name,
                arguments=args,
                tokens_used=tokens,
            )

        # Parse final verdict if returned as text
        content = choice.content or ""
        try:
            parsed = json.loads(content)
            verdict = TriageVerdict.model_validate(parsed)
            return ToolCallResponse(is_verdict=True, verdict=verdict, tokens_used=tokens)
        except Exception:
            # Fallback verdict
            return ToolCallResponse(
                is_verdict=True,
                verdict=TriageVerdict(
                    severity=SeverityLevel.P2,
                    root_cause_category="UNPARSED_LLM_OUTPUT",
                    is_duplicate=False,
                    reproduction_confirmed=False,
                    recommended_action="Manually review raw agent output.",
                    confidence_score=0.5,
                    status=TriageStatus.COMPLETE,
                ),
                tokens_used=tokens,
            )


class MockLLMProvider(LLMProvider):
    """Deterministic, scenario-aware offline LLM simulator for reproducible zero-API testing."""

    def __init__(self, mode: str = "auto") -> None:
        """
        Modes:
        - 'auto': Inspects ticket hints / conversation history to simulate realistic triage steps
        - 'trigger_malformed_first': Emits malformed arguments on first call, then self-heals after validation feedback
        - 'trigger_loop': Emits duplicate identical tool calls to test loop detector
        """
        self.mode = mode
        self.call_count = 0

    async def decide_next_step(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> ToolCallResponse:
        self.call_count += 1
        last_message = messages[-1]["content"] if messages else ""

        # Check if previous step was a validation failure feedback
        is_retry = "VALIDATION_FAILED" in str(last_message) or "Schema validation failed" in str(last_message)

        # Scenario 1: Deliberate Malformed Recovery mode
        if self.mode == "trigger_malformed_first":
            if not is_retry and self.call_count == 1:
                # Return malformed arguments (e.g. invalid negative minutes_back for log query)
                return ToolCallResponse(
                    is_verdict=False,
                    tool_name="query_service_logs",
                    arguments={"service_name": "checkout-service", "severity": "ERROR", "minutes_back": -50},
                    tokens_used=120,
                )
            if is_retry:
                # Self-healing: Emit corrected arguments after receiving validation error!
                return ToolCallResponse(
                    is_verdict=False,
                    tool_name="query_service_logs",
                    arguments={"service_name": "checkout-service", "severity": "ERROR", "minutes_back": 30},
                    tokens_used=110,
                )
            # After successful retry, output complete verdict
            return ToolCallResponse(
                is_verdict=True,
                verdict=TriageVerdict(
                    severity=SeverityLevel.P2,
                    root_cause_category="CLIENT_VALIDATION_ERROR",
                    is_duplicate=False,
                    duplicate_ticket_id=None,
                    reproduction_confirmed=True,
                    recommended_action="Applied self-healing schema retry. Fix schema validation in log consumer.",
                    confidence_score=0.92,
                    status=TriageStatus.COMPLETE,
                ),
                tokens_used=150,
            )

        # Scenario 2: Deliberate Loop Trigger mode
        if self.mode == "trigger_loop":
            # Always emit the identical tool call
            return ToolCallResponse(
                is_verdict=False,
                tool_name="search_duplicate_issues",
                arguments={"query_text": "NullPointerException in checkout", "top_k": 3},
                tokens_used=100,
            )

        # Scenario 3: Auto mode - state machine tracking executed tools
        has_searched = any(m.get("name") == "search_duplicate_issues" for m in messages)
        has_replayed = any(m.get("name") == "replay_http_endpoint" for m in messages)
        has_queried_logs = any(m.get("name") == "query_service_logs" for m in messages)

        # Find latest tool message output
        last_tool_msg = None
        for m in reversed(messages):
            if m.get("role") == "tool":
                try:
                    last_tool_msg = json.loads(m.get("content", "{}"))
                except Exception:
                    last_tool_msg = {}
                break

        # Extract ticket context
        ticket_text = ""
        for m in messages:
            if "<untrusted_ticket_data>" in str(m.get("content")):
                ticket_text = str(m.get("content"))
                break

        # Check if ticket contains injection indicator
        if "ignore previous instructions" in ticket_text.lower() or "disregard all" in ticket_text.lower():
            return ToolCallResponse(
                is_verdict=True,
                verdict=TriageVerdict(
                    severity=SeverityLevel.P1,
                    root_cause_category="ADVERSARIAL_INJECTION_QUARANTINED",
                    is_duplicate=False,
                    reproduction_confirmed=False,
                    recommended_action="Quarantine ticket and block malicious submitter.",
                    confidence_score=1.0,
                    status=TriageStatus.QUARANTINED_INJECTION,
                ),
                tokens_used=100,
            )

        # Step 1: Duplicate check
        if not has_searched:
            return ToolCallResponse(
                is_verdict=False,
                tool_name="search_duplicate_issues",
                arguments={"query_text": ticket_text[:120] or "Bug report reproduction", "top_k": 3},
                tokens_used=140,
            )

        # If duplicate search just ran and found historical duplicate
        if has_searched and not has_replayed and last_tool_msg:
            top_matches = last_tool_msg.get("top_matches", [])
            if top_matches and (
                "duplicate" in ticket_text.lower()
                or "identical to known" in ticket_text.lower()
                or "tick-hist-" in ticket_text.lower()
                or (top_matches[0].get("similarity_score", 0) > 0.85)
            ):
                top = top_matches[0]
                return ToolCallResponse(
                    is_verdict=True,
                    verdict=TriageVerdict(
                        severity=SeverityLevel(top.get("severity", "P1")),
                        root_cause_category=top.get("category", "DUPLICATE_ISSUE"),
                        is_duplicate=True,
                        duplicate_ticket_id=top.get("ticket_id"),
                        reproduction_confirmed=True,
                        recommended_action=f"Mark as duplicate of {top.get('ticket_id')}. Resolution: {top.get('resolution')}",
                        confidence_score=0.96,
                        status=TriageStatus.COMPLETE,
                    ),
                    tokens_used=180,
                )

        # Step 2: Replay endpoint
        if not has_replayed:
            path = "/api/v1/checkout"
            method = "POST"
            payload = {"cart_id": "cart_test_1", "payment_method": "card", "items": [{"id": "item1"}]}
            if "profile" in ticket_text.lower():
                path = "/api/v1/profile"
                method = "GET"
                payload = None
            elif "orders" in ticket_text.lower():
                path = "/api/v1/orders"
                method = "GET"
                payload = None

            return ToolCallResponse(
                is_verdict=False,
                tool_name="replay_http_endpoint",
                arguments={"method": method, "path": path, "payload": payload},
                tokens_used=160,
            )

        # Check replay output for circuit breaker / 503 / SSRF
        if last_tool_msg:
            error_str = str(last_tool_msg.get("error", ""))
            status_code = last_tool_msg.get("status_code")
            if "CIRCUIT_BREAKER_OPEN" in error_str or status_code == 503 or "503" in ticket_text:
                return ToolCallResponse(
                    is_verdict=True,
                    verdict=TriageVerdict(
                        severity=SeverityLevel.P0,
                        root_cause_category="503_UPSTREAM_UNAVAILABLE",
                        is_duplicate=False,
                        reproduction_confirmed=True,
                        recommended_action="Escalate to platform on-call: Upstream gateway pool failure, circuit breaker tripped.",
                        confidence_score=0.95,
                        status=TriageStatus.COMPLETE,
                    ),
                    tokens_used=150,
                )
            if "SECURITY_BLOCK_SSRF" in error_str:
                return ToolCallResponse(
                    is_verdict=True,
                    verdict=TriageVerdict(
                        severity=SeverityLevel.P0,
                        root_cause_category="SECURITY_BLOCK_SSRF",
                        is_duplicate=False,
                        reproduction_confirmed=False,
                        recommended_action="Reject replay: Target blocked by SSRFGuard sandbox allowlist.",
                        confidence_score=1.0,
                        status=TriageStatus.COMPLETE,
                    ),
                    tokens_used=150,
                )

        # Step 3: Query logs
        if not has_queried_logs:
            return ToolCallResponse(
                is_verdict=False,
                tool_name="query_service_logs",
                arguments={"service_name": "checkout-service", "severity": "ERROR", "minutes_back": 60},
                tokens_used=130,
            )

        # Step 4: Final verdict for normal bugs
        severity = SeverityLevel.P2
        root_cause = "SERVICE_ERROR"
        if "null" in str(last_message).lower() or "500" in str(last_message) or "null" in ticket_text.lower():
            severity = SeverityLevel.P1
            root_cause = "NULL_POINTER_EXCEPTION"
        elif "latency" in ticket_text.lower():
            severity = SeverityLevel.P2
            root_cause = "LATENCY_SPIKE"
        elif "malformed" in ticket_text.lower():
            severity = SeverityLevel.P2
            root_cause = "MALFORMED_JSON_ERROR"

        return ToolCallResponse(
            is_verdict=True,
            verdict=TriageVerdict(
                severity=severity,
                root_cause_category=root_cause,
                is_duplicate=False,
                duplicate_ticket_id=None,
                reproduction_confirmed=True,
                recommended_action=f"Investigate {root_cause} logs and apply service patch.",
                confidence_score=0.90,
                status=TriageStatus.COMPLETE,
            ),
            tokens_used=180,
        )
