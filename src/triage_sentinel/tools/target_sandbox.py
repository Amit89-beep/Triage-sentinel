"""Target Sandbox microservice simulating backend services with toggleable chaos modes."""

from __future__ import annotations

import asyncio
from enum import Enum
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel


class ChaosMode(str, Enum):
    NORMAL = "normal"
    LATENCY_SPIKE = "latency_spike"
    HTTP_503_STORM = "http_503_storm"
    NULL_POINTER_500 = "null_pointer_500"
    MALFORMED_JSON = "malformed_json"


class SandboxConfig:
    """Thread-safe configuration for sandbox chaos state."""

    def __init__(self, mode: ChaosMode = ChaosMode.NORMAL, latency_seconds: float = 2.5) -> None:
        self.mode = mode
        self.latency_seconds = latency_seconds
        self.request_counter = 0

    def set_mode(self, mode: ChaosMode, latency_seconds: Optional[float] = None) -> None:
        self.mode = mode
        if latency_seconds is not None:
            self.latency_seconds = latency_seconds

    def get_mode(self) -> ChaosMode:
        return self.mode


class CheckoutPayload(BaseModel):
    cart_id: str
    payment_method: str
    items: list[Dict[str, Any]]
    coupon_code: Optional[str] = None


class OrderPayload(BaseModel):
    order_id: Optional[str] = None
    customer_id: str
    amount: float


def create_sandbox_app(config: Optional[SandboxConfig] = None) -> FastAPI:
    """Creates a configured FastAPI sandbox instance."""
    app = FastAPI(title="Triage Sentinel Target Sandbox", version="1.0.0")
    cfg = config or SandboxConfig()

    @app.middleware("http")
    async def chaos_middleware(request: Request, call_next):
        cfg.request_counter += 1
        path = request.url.path

        # Do not inject chaos into the control plane endpoint
        if path.startswith("/api/v1/chaos"):
            return await call_next(request)

        current_mode = cfg.get_mode()

        if current_mode == ChaosMode.LATENCY_SPIKE:
            await asyncio.sleep(cfg.latency_seconds)

        elif current_mode == ChaosMode.HTTP_503_STORM:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Upstream gateway failure: downstream replica pool saturated",
                    "code": 503,
                },
            )

        elif current_mode == ChaosMode.NULL_POINTER_500:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "NullPointerException",
                    "exception": "java.lang.NullPointerException: Cannot invoke 'payment_gateway.authorize()' because object is null",
                    "service": "checkout-service",
                    "code": 500,
                },
            )

        elif current_mode == ChaosMode.MALFORMED_JSON:
            return Response(
                content=b'{"status": "error", "corrupted": [true, false,,], "unclosed_bracket": {',
                status_code=200,
                media_type="application/json",
            )

        return await call_next(request)

    # Control plane endpoints
    @app.get("/api/v1/chaos/mode")
    async def get_chaos_mode():
        return {
            "mode": cfg.get_mode().value,
            "latency_seconds": cfg.latency_seconds,
            "requests_processed": cfg.request_counter,
        }

    @app.post("/api/v1/chaos/mode")
    async def set_chaos_mode(payload: Dict[str, Any]):
        mode_str = payload.get("mode")
        latency = payload.get("latency_seconds")
        try:
            mode = ChaosMode(mode_str)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid chaos mode: {mode_str}. Valid modes: {[m.value for m in ChaosMode]}",
            )
        cfg.set_mode(mode, latency)
        return {"status": "ok", "mode": cfg.get_mode().value}

    # Microservice simulation endpoints
    @app.post("/api/v1/checkout")
    async def checkout(payload: CheckoutPayload):
        if not payload.items:
            raise HTTPException(status_code=422, detail="Cart cannot be empty")
        return {
            "status": "success",
            "transaction_id": "tx_live_99214a",
            "cart_id": payload.cart_id,
            "amount_charged": 149.99,
        }

    @app.get("/api/v1/profile")
    async def profile(user_id: Optional[str] = "usr_default"):
        return {
            "user_id": user_id,
            "name": "Jane Developer",
            "tier": "enterprise",
            "status": "active",
        }

    @app.get("/api/v1/orders")
    async def list_orders(limit: int = 10):
        return {
            "orders": [
                {"id": "ord_101", "status": "completed", "total": 45.0},
                {"id": "ord_102", "status": "processing", "total": 120.50},
            ],
            "total_count": 2,
        }

    @app.post("/api/v1/orders")
    async def create_order(payload: OrderPayload):
        return {
            "order_id": payload.order_id or "ord_generated_554",
            "customer_id": payload.customer_id,
            "amount": payload.amount,
            "status": "created",
        }

    return app
