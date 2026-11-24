"""MCP Server implementation exposing bug-triage tools backed by sandbox & ChromaDB."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
import chromadb
import httpx
from httpx import ASGITransport

from mcp.server.mcpserver import MCPServer
from triage_sentinel.guardrails.sanitizer import SSRFGuard
from triage_sentinel.guardrails.circuit_breaker import ToolCircuitBreaker
from triage_sentinel.models.schemas import (
    DuplicateSearchRequest,
    LogQueryRequest,
    ReplayRequest,
)
from triage_sentinel.tools.target_sandbox import SandboxConfig, create_sandbox_app


HISTORICAL_TICKETS = [
    {
        "id": "TICK-HIST-101",
        "title": "NullPointerException in CheckoutService when processing empty coupon code",
        "body": "Replaying POST /api/v1/checkout with empty coupon string causes null pointer crash in payment authorization.",
        "resolution": "Fixed in PR #412: Added null check and validation for coupon_code parameter.",
        "category": "NULL_POINTER_EXCEPTION",
        "severity": "P1",
    },
    {
        "id": "TICK-HIST-102",
        "title": "503 Service Unavailable during order sync batch job due to upstream gateway saturation",
        "body": "Burst requests to /api/v1/orders cause HTTP 503 storm when downstream connection pool exhausts.",
        "resolution": "Applied circuit breaker pattern and increased connection pool limit in gateway config.",
        "category": "503_UPSTREAM_UNAVAILABLE",
        "severity": "P0",
    },
    {
        "id": "TICK-HIST-103",
        "title": "Profile endpoint latency spike due to unindexed query on user_preferences",
        "body": "GET /api/v1/profile experiences 3000ms latency under moderate load due to table scan.",
        "resolution": "Added composite index on (user_id, preference_id). Response times dropped to 15ms.",
        "category": "LATENCY_SPIKE",
        "severity": "P2",
    },
    {
        "id": "TICK-HIST-104",
        "title": "Malformed JSON response returned from legacy auth middleware on corrupted bearer token",
        "body": "When auth token header is corrupted, middleware emits invalid JSON with duplicate commas.",
        "resolution": "Upgraded auth middleware tokenizer to catch format errors cleanly and return 401 JSON.",
        "category": "MALFORMED_JSON_ERROR",
        "severity": "P2",
    },
    {
        "id": "TICK-HIST-105",
        "title": "Database connection timeout during primary-replica failover in orders service",
        "body": "Transient connection drop causes queries to hang until 30s socket timeout fires.",
        "resolution": "Configured health checks with 2s timeout and automatic failover retries with backoff.",
        "category": "DATABASE_TIMEOUT",
        "severity": "P1",
    },
    {
        "id": "TICK-HIST-106",
        "title": "Validation error 422 when items array is empty during order checkout",
        "body": "POST /api/v1/checkout returns HTTP 422 Unprocessable Entity when items list is empty.",
        "resolution": "Expected client-side validation behavior. Added frontend pre-validation guard.",
        "category": "CLIENT_VALIDATION_ERROR",
        "severity": "P3",
    },
    {
        "id": "TICK-HIST-107",
        "title": "Memory leak in background analytics event consumer causing worker OOM crash",
        "body": "Unbounded queue in kafka consumer accumulates uncommitted payloads until container terminates.",
        "resolution": "Bounded queue size and enabled batch backpressure throttling.",
        "category": "MEMORY_LEAK_OOM",
        "severity": "P1",
    },
    {
        "id": "TICK-HIST-108",
        "title": "Session invalidation failure when user changes password across multiple devices",
        "body": "Tokens stored in local cache are not revoked on password reset until TTL expires.",
        "resolution": "Broadcasted redis pub/sub invalidation event on credential updates.",
        "category": "SECURITY_SESSION_REVOCATION",
        "severity": "P1",
    },
]


class SentinelMCPServer:
    """Production-grade MCP server providing triage diagnostics with circuit breakers."""

    def __init__(
        self,
        sandbox_config: Optional[SandboxConfig] = None,
        circuit_cooldown_seconds: float = 5.0,
    ) -> None:
        self.sandbox_config = sandbox_config or SandboxConfig()
        self.sandbox_app = create_sandbox_app(self.sandbox_config)
        self.http_client = httpx.AsyncClient(
            transport=ASGITransport(app=self.sandbox_app),
            base_url="http://sandbox",
            timeout=1.5,
        )

        # Per-tool circuit breakers
        self.circuit_breakers: Dict[str, ToolCircuitBreaker] = {
            "replay_http_endpoint": ToolCircuitBreaker(
                "replay_http_endpoint", failure_threshold=3, cooldown_seconds=circuit_cooldown_seconds
            ),
            "query_service_logs": ToolCircuitBreaker(
                "query_service_logs", failure_threshold=3, cooldown_seconds=circuit_cooldown_seconds
            ),
            "search_duplicate_issues": ToolCircuitBreaker(
                "search_duplicate_issues", failure_threshold=3, cooldown_seconds=circuit_cooldown_seconds
            ),
        }

        # Initialize ChromaDB ephemeral vector store
        self.chroma_client = chromadb.Client()
        self.collection_name = "historical_bug_tickets"
        try:
            self.chroma_client.delete_collection(self.collection_name)
        except Exception:
            pass
        self.collection = self.chroma_client.create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._seed_historical_tickets()

        # Initialize underlying MCP server
        self.server = MCPServer("TriageSentinel")
        self._register_mcp_tools()

    def _seed_historical_tickets(self) -> None:
        """Seeds the 8 reference historical tickets into ChromaDB."""
        docs = [f"{t['title']}\n{t['body']}" for t in HISTORICAL_TICKETS]
        ids = [t["id"] for t in HISTORICAL_TICKETS]
        metadatas = [
            {
                "title": t["title"],
                "resolution": t["resolution"],
                "category": t["category"],
                "severity": t["severity"],
            }
            for t in HISTORICAL_TICKETS
        ]
        self.collection.add(documents=docs, ids=ids, metadatas=metadatas)

    def _register_mcp_tools(self) -> None:
        """Exposes the tools over MCP standard protocol."""

        @self.server.tool()
        async def replay_http_endpoint(
            method: str, path: str, payload: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
            """Replay an HTTP request against the target sandbox microservice."""
            return await self.execute_replay_http_endpoint(method, path, payload)

        @self.server.tool()
        async def query_service_logs(
            service_name: str, severity: str, minutes_back: int
        ) -> Dict[str, Any]:
            """Query centralized microservice logs for error diagnostics."""
            return await self.execute_query_service_logs(service_name, severity, minutes_back)

        @self.server.tool()
        async def search_duplicate_issues(query_text: str, top_k: int = 3) -> Dict[str, Any]:
            """Search ChromaDB collection of historical bug reports for duplicates."""
            return await self.execute_search_duplicate_issues(query_text, top_k)

    async def execute_replay_http_endpoint(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Internal execution with SSRF guard and circuit breaker protection."""
        cb = self.circuit_breakers["replay_http_endpoint"]
        if not cb.can_execute():
            return {
                "success": False,
                "error": "CIRCUIT_BREAKER_OPEN: replay_http_endpoint is tripped due to consecutive failures/timeouts.",
                "circuit_state": cb.get_state().value,
            }

        # Validate with SSRF guard
        try:
            validated_path = SSRFGuard.validate_path(path)
        except ValueError as e:
            # SSRF violation is an operational security block
            return {
                "success": False,
                "error": f"SECURITY_BLOCK_SSRF: {str(e)}",
                "circuit_state": cb.get_state().value,
            }

        try:
            response = await self.http_client.request(
                method=method.upper(),
                url=validated_path,
                json=payload,
            )

            # Determine response parsing
            content_type = response.headers.get("content-type", "")
            try:
                body = response.json()
            except Exception:
                body = response.text

            # Check if this response indicates a service failure that trips circuit breaker
            if response.status_code >= 500:
                cb.record_failure()
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "body": body,
                    "error": f"HTTP {response.status_code} Server Error",
                    "circuit_state": cb.get_state().value,
                }

            cb.record_success()
            return {
                "success": True,
                "status_code": response.status_code,
                "body": body,
                "headers": dict(response.headers),
                "circuit_state": cb.get_state().value,
            }

        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            cb.record_failure()
            return {
                "success": False,
                "error": f"HTTP Request Timeout / Connection Failure: {type(exc).__name__}",
                "circuit_state": cb.get_state().value,
            }
        except Exception as exc:
            cb.record_failure()
            return {
                "success": False,
                "error": f"Unexpected execution error: {str(exc)}",
                "circuit_state": cb.get_state().value,
            }

    async def execute_query_service_logs(
        self, service_name: str, severity: str, minutes_back: int
    ) -> Dict[str, Any]:
        """Simulated service log retrieval with circuit breaker protection."""
        cb = self.circuit_breakers["query_service_logs"]
        if not cb.can_execute():
            return {
                "success": False,
                "error": "CIRCUIT_BREAKER_OPEN: query_service_logs is tripped.",
                "circuit_state": cb.get_state().value,
            }

        # Realistic log lines generation based on current chaos mode and parameters
        current_chaos = self.sandbox_config.get_mode().value
        logs = []

        if "503" in current_chaos:
            logs.append({
                "timestamp": "2026-11-24T11:00:01Z",
                "service": service_name,
                "severity": "ERROR",
                "message": "GatewayTimeout: Upstream connection pool exhausted (503 Service Unavailable)",
            })
            logs.append({
                "timestamp": "2026-11-24T11:00:03Z",
                "service": service_name,
                "severity": "CRITICAL",
                "message": "CircuitBreaker trip initiated: downstream cluster unhealthy",
            })
        elif "500" in current_chaos:
            logs.append({
                "timestamp": "2026-11-24T11:00:01Z",
                "service": service_name,
                "severity": "ERROR",
                "message": "NullPointerException at com.sentinel.service.CheckoutService.processPayment(CheckoutService.java:142)",
            })
        elif "latency" in current_chaos:
            logs.append({
                "timestamp": "2026-11-24T11:00:01Z",
                "service": service_name,
                "severity": "WARNING",
                "message": "Slow query warning: duration=2850ms path=/api/v1/profile caller=gateway",
            })
        else:
            logs.append({
                "timestamp": "2026-11-24T11:00:01Z",
                "service": service_name,
                "severity": severity,
                "message": f"Service operation completed normally in {service_name}",
            })

        cb.record_success()
        return {
            "success": True,
            "service_name": service_name,
            "severity_filter": severity,
            "minutes_back": minutes_back,
            "logs_count": len(logs),
            "logs": logs,
            "circuit_state": cb.get_state().value,
        }

    async def execute_search_duplicate_issues(
        self, query_text: str, top_k: int = 3
    ) -> Dict[str, Any]:
        """Queries ChromaDB vector collection for semantically similar bug tickets."""
        cb = self.circuit_breakers["search_duplicate_issues"]
        if not cb.can_execute():
            return {
                "success": False,
                "error": "CIRCUIT_BREAKER_OPEN: search_duplicate_issues is tripped.",
                "circuit_state": cb.get_state().value,
            }

        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=min(top_k, len(HISTORICAL_TICKETS)),
            )

            matches = []
            if results and results.get("ids") and len(results["ids"]) > 0:
                for idx, ticket_id in enumerate(results["ids"][0]):
                    metadata = results["metadatas"][0][idx] if results.get("metadatas") else {}
                    distance = results["distances"][0][idx] if results.get("distances") else 0.5
                    # Convert distance to similarity score
                    similarity = max(0.0, min(1.0, 1.0 - distance))
                    matches.append({
                        "ticket_id": ticket_id,
                        "title": metadata.get("title", ""),
                        "category": metadata.get("category", ""),
                        "resolution": metadata.get("resolution", ""),
                        "similarity_score": round(similarity, 3),
                    })

            cb.record_success()
            return {
                "success": True,
                "query": query_text,
                "total_matches": len(matches),
                "top_matches": matches,
                "circuit_state": cb.get_state().value,
            }

        except Exception as exc:
            cb.record_failure()
            return {
                "success": False,
                "error": f"ChromaDB search failure: {str(exc)}",
                "circuit_state": cb.get_state().value,
            }

    async def aclose(self) -> None:
        """Closes HTTP client resources cleanly."""
        await self.http_client.aclose()
