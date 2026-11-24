"""Self-healing orchestrator with schema validation retries and telemetry."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import ValidationError

from triage_sentinel.guardrails.circuit_breaker import RunBudgetTracker
from triage_sentinel.guardrails.sanitizer import PromptInjectionGuard, SSRFGuard
from triage_sentinel.models.schemas import (
    CircuitState,
    DuplicateSearchRequest,
    ExecutionTrace,
    LogQueryRequest,
    ReplayRequest,
    SeverityLevel,
    StepTrace,
    TicketInput,
    TriageStatus,
    TriageVerdict,
)
from triage_sentinel.runtime.llm_provider import LLMProvider, MockLLMProvider
from triage_sentinel.tools.mcp_server import SentinelMCPServer


SYSTEM_PROMPT = """You are Triage Sentinel, an autonomous bug triage agent with diagnostic tools.
Analyze untrusted bug reports, search historical duplicates in ChromaDB, replay sandbox endpoints, and query logs.
When done, output a final structured verdict JSON matching TriageVerdict schema."""

AVAILABLE_TOOLS_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "replay_http_endpoint",
            "description": "Replay an HTTP request against the local sandbox backend (/api/...).",
            "parameters": ReplayRequest.model_json_schema(),
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_service_logs",
            "description": "Fetch centralized microservice logs for diagnosis.",
            "parameters": LogQueryRequest.model_json_schema(),
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_duplicate_issues",
            "description": "Query ChromaDB historical tickets for semantic duplicate detection.",
            "parameters": DuplicateSearchRequest.model_json_schema(),
        },
    },
]


class TriageOrchestrator:
    """State-machine orchestrator ensuring schema compliance, budget safety, and telemetry."""

    TOOL_SCHEMA_MAP = {
        "replay_http_endpoint": ReplayRequest,
        "query_service_logs": LogQueryRequest,
        "search_duplicate_issues": DuplicateSearchRequest,
    }

    def __init__(
        self,
        mcp_server: Optional[SentinelMCPServer] = None,
        llm_provider: Optional[LLMProvider] = None,
        max_steps: int = 6,
        max_tokens: int = 12000,
        max_wall_seconds: float = 30.0,
        max_validation_retries: int = 2,
    ) -> None:
        self.mcp_server = mcp_server or SentinelMCPServer()
        self.llm_provider = llm_provider or MockLLMProvider()
        self.max_steps = max_steps
        self.max_tokens = max_tokens
        self.max_wall_seconds = max_wall_seconds
        self.max_validation_retries = max_validation_retries

    async def triage(self, ticket: TicketInput) -> ExecutionTrace:
        """Executes the complete self-healing triage lifecycle for a bug ticket."""
        run_id = f"run_{uuid.uuid4().hex[:8]}"
        trace = ExecutionTrace(run_id=run_id, ticket_id=ticket.ticket_id)
        start_time = time.monotonic()

        # Step 0: Prompt Injection Guardrail Inspection
        is_injected, injection_reason = PromptInjectionGuard.inspect(ticket)
        if is_injected:
            verdict = TriageVerdict(
                severity=SeverityLevel.P1,
                root_cause_category="ADVERSARIAL_PROMPT_INJECTION",
                is_duplicate=False,
                reproduction_confirmed=False,
                recommended_action=f"Quarantine ticket immediately. Injection signature: {injection_reason}",
                confidence_score=1.0,
                status=TriageStatus.QUARANTINED_INJECTION,
            )
            step_record = StepTrace(
                step_number=1,
                tool_name="guardrail_prompt_injection",
                raw_arguments={"title": ticket.title, "body_preview": ticket.body[:80]},
                latency_ms=1.2,
                circuit_state="CLOSED",
                output={"quarantined": True, "reason": injection_reason},
            )
            trace.steps.append(step_record)
            trace.final_verdict = verdict
            trace.total_latency_ms = (time.monotonic() - start_time) * 1000.0
            return trace

        # Budget Tracker & Secure Delimiting
        budget = RunBudgetTracker(
            max_steps=self.max_steps,
            max_tokens=self.max_tokens,
            max_wall_seconds=self.max_wall_seconds,
        )

        wrapped_body = PromptInjectionGuard.wrap_payload(ticket.body)
        messages: List[Dict[str, Any]] = [
            {
                "role": "user",
                "content": f"New Ticket to Triage:\nID: {ticket.ticket_id}\nTitle: {ticket.title}\nReporter: {ticket.reporter}\nEndpoint Hint: {ticket.endpoint_hint or 'None'}\n\nContent:\n{wrapped_body}",
            }
        ]

        step_counter = 0

        while True:
            # Check budget limits before scheduling next LLM step
            is_budget_ok, budget_reason = budget.check_budget()
            if not is_budget_ok:
                trace.final_verdict = TriageVerdict(
                    severity=SeverityLevel.P2,
                    root_cause_category="PARTIAL_BUDGET_EXCEEDED",
                    is_duplicate=False,
                    reproduction_confirmed=False,
                    recommended_action=f"Triage halted: {budget_reason}. Review partial diagnostic steps.",
                    confidence_score=0.4,
                    status=TriageStatus.PARTIAL_BUDGET_EXCEEDED,
                )
                break

            step_counter += 1
            step_start = time.monotonic()

            # Query LLM for next decision
            llm_response = await self.llm_provider.decide_next_step(
                system_prompt=SYSTEM_PROMPT,
                messages=messages,
                available_tools=AVAILABLE_TOOLS_SPECS,
            )

            budget.record_step(tokens_used=llm_response.tokens_used)
            trace.total_tokens += llm_response.tokens_used

            # Case A: LLM produced a final verdict
            if llm_response.is_verdict and llm_response.verdict is not None:
                trace.final_verdict = llm_response.verdict
                step_record = StepTrace(
                    step_number=step_counter,
                    tool_name="final_verdict",
                    latency_ms=(time.monotonic() - step_start) * 1000.0,
                    output=llm_response.verdict.model_dump(),
                )
                trace.steps.append(step_record)
                break

            # Case B: LLM invoked a tool
            tool_name = llm_response.tool_name
            raw_args = llm_response.arguments or {}

            if not tool_name or tool_name not in self.TOOL_SCHEMA_MAP:
                # Unrecognized tool: feedback and continue
                messages.append({
                    "role": "user",
                    "content": f"Error: Tool '{tool_name}' does not exist. Available tools: {list(self.TOOL_SCHEMA_MAP.keys())}",
                })
                continue

            schema_cls = self.TOOL_SCHEMA_MAP[tool_name]
            validated_args: Optional[Dict[str, Any]] = None
            validation_retries = 0

            # Self-healing Schema Validation Retry Loop
            current_raw_args = raw_args
            while validation_retries <= self.max_validation_retries:
                try:
                    parsed_model = schema_cls.model_validate(current_raw_args)
                    validated_args = parsed_model.model_dump()
                    break
                except ValidationError as ve:
                    validation_retries += 1
                    trace.total_validation_retries += 1

                    if validation_retries > self.max_validation_retries:
                        break

                    # Feed structured ValidationError back to LLM for self-healing
                    error_details = [
                        f"Field '{e['loc'][0]}': {e['msg']} (got {e.get('input')})"
                        for e in ve.errors()
                    ]
                    error_feedback = (
                        f"VALIDATION_FAILED for tool '{tool_name}':\n"
                        + "\n".join(error_details)
                        + "\nPlease rectify tool arguments strictly adhering to the schema."
                    )
                    messages.append({"role": "user", "content": error_feedback})

                    # Prompt LLM again for corrected call
                    retry_resp = await self.llm_provider.decide_next_step(
                        system_prompt=SYSTEM_PROMPT,
                        messages=messages,
                        available_tools=AVAILABLE_TOOLS_SPECS,
                    )
                    budget.record_step(tokens_used=retry_resp.tokens_used)
                    trace.total_tokens += retry_resp.tokens_used

                    if retry_resp.is_verdict:
                        llm_response = retry_resp
                        break
                    current_raw_args = retry_resp.arguments or {}

            if llm_response.is_verdict and llm_response.verdict is not None:
                trace.final_verdict = llm_response.verdict
                break

            if validated_args is None:
                # Exhausted validation retries without valid arguments
                step_record = StepTrace(
                    step_number=step_counter,
                    tool_name=tool_name,
                    raw_arguments=raw_args,
                    validation_retries=validation_retries,
                    error="SCHEMA_VALIDATION_EXHAUSTED",
                    latency_ms=(time.monotonic() - step_start) * 1000.0,
                )
                trace.steps.append(step_record)
                messages.append({
                    "role": "user",
                    "content": f"Schema validation retries exhausted for tool '{tool_name}'. Proceeding to next step.",
                })
                continue

            # Loop Detection Guardrail
            is_new_action, loop_err = budget.register_action(tool_name, validated_args)
            if not is_new_action:
                step_record = StepTrace(
                    step_number=step_counter,
                    tool_name=tool_name,
                    raw_arguments=raw_args,
                    validated_arguments=validated_args,
                    validation_retries=validation_retries,
                    error=loop_err,
                    latency_ms=(time.monotonic() - step_start) * 1000.0,
                )
                trace.steps.append(step_record)
                messages.append({
                    "role": "user",
                    "content": f"LOOP_DETECTED: {loop_err}. Do not repeat previous actions. Provide final verdict.",
                })
                continue

            # Tool Circuit Breaker State Check
            cb = self.mcp_server.circuit_breakers.get(tool_name)
            current_circuit_state = cb.get_state().value if cb else "CLOSED"

            # Execute tool through MCP server
            tool_output: Dict[str, Any]
            if tool_name == "replay_http_endpoint":
                tool_output = await self.mcp_server.execute_replay_http_endpoint(
                    method=validated_args["method"],
                    path=validated_args["path"],
                    payload=validated_args.get("payload"),
                )
            elif tool_name == "query_service_logs":
                tool_output = await self.mcp_server.execute_query_service_logs(
                    service_name=validated_args["service_name"],
                    severity=validated_args["severity"],
                    minutes_back=validated_args["minutes_back"],
                )
            elif tool_name == "search_duplicate_issues":
                tool_output = await self.mcp_server.execute_search_duplicate_issues(
                    query_text=validated_args["query_text"],
                    top_k=validated_args.get("top_k", 3),
                )
            else:
                tool_output = {"error": f"Unsupported tool {tool_name}"}

            # Check if circuit tripped
            updated_circuit_state = cb.get_state().value if cb else "CLOSED"
            if updated_circuit_state == "OPEN":
                trace.circuit_breaks_triggered += 1

            latency = (time.monotonic() - step_start) * 1000.0
            step_record = StepTrace(
                step_number=step_counter,
                tool_name=tool_name,
                raw_arguments=raw_args,
                validated_arguments=validated_args,
                latency_ms=latency,
                validation_retries=validation_retries,
                circuit_state=updated_circuit_state,
                output=tool_output,
            )
            trace.steps.append(step_record)

            # Append tool output to LLM messages
            messages.append({
                "role": "tool",
                "name": tool_name,
                "content": json.dumps(tool_output),
            })

        trace.total_latency_ms = (time.monotonic() - start_time) * 1000.0
        return trace
