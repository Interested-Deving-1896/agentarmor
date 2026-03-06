"""AgentArmor Proxy Server — sits between agent runtimes and LLM/tool APIs."""

from __future__ import annotations

import json
import time
from typing import Any

from agentarmor.core.config import ArmorConfig
from agentarmor.core.types import AgentEvent
from agentarmor.pipeline import AgentArmor


def create_app(config: ArmorConfig | None = None):
    """Create the FastAPI proxy application."""
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import JSONResponse

    app = FastAPI(
        title="AgentArmor Proxy",
        description="Security proxy for agentic AI applications",
        version="0.1.0",
    )

    armor = AgentArmor(config=config or ArmorConfig())

    @app.get("/health")
    async def health():
        return {"status": "healthy", "version": "0.1.0"}

    @app.post("/v1/intercept")
    async def intercept(request: Request):
        """Intercept and validate an agent action."""
        body = await request.json()
        result = await armor.intercept(
            action=body.get("action", ""),
            params=body.get("params", {}),
            agent_id=body.get("agent_id", "default"),
            context=body.get("context", {}),
            input_data=body.get("input_data"),
            output_data=body.get("output_data"),
        )
        return JSONResponse(
            content={
                "verdict": result.final_verdict.value,
                "threat_level": result.final_threat_level.value,
                "is_safe": result.is_safe,
                "blocked_by": result.blocked_by,
                "processing_time_ms": round(result.total_processing_time_ms, 2),
                "layers": [
                    {
                        "layer": lr.layer,
                        "verdict": lr.verdict.value,
                        "message": lr.message,
                    }
                    for lr in result.layer_results
                ],
            },
            status_code=200 if result.is_safe else 403,
        )

    @app.post("/v1/scan/input")
    async def scan_input(request: Request):
        """Scan input data for threats (prompt injection, etc.)."""
        body = await request.json()
        event = AgentEvent(
            agent_id=body.get("agent_id", "scanner"),
            event_type="scan",
            action="scan.input",
            input_data=body.get("text", ""),
        )
        result = await armor.process(event)
        return JSONResponse(
            content={
                "verdict": result.final_verdict.value,
                "is_safe": result.is_safe,
                "details": [
                    {"layer": lr.layer, "verdict": lr.verdict.value, "message": lr.message}
                    for lr in result.layer_results if lr.verdict != "allow"
                ],
            }
        )

    @app.post("/v1/scan/output")
    async def scan_output(request: Request):
        """Scan output data for PII and sensitive content."""
        body = await request.json()
        event = AgentEvent(
            agent_id=body.get("agent_id", "scanner"),
            event_type="scan_output",
            action="scan.output",
            output_data=body.get("text", ""),
        )
        result = await armor.scan_output(event)
        return JSONResponse(
            content={
                "verdict": result.verdict.value,
                "message": result.message,
                "redacted_text": result.modified_data,
            }
        )

    @app.get("/v1/audit")
    async def get_audit(agent_id: str | None = None, limit: int = 100):
        """Retrieve audit trail."""
        entries = armor.audit.get_audit_trail(agent_id=agent_id, limit=limit)
        return JSONResponse(content={"entries": entries, "count": len(entries)})

    @app.get("/v1/audit/verify")
    async def verify_audit():
        """Verify audit log integrity."""
        is_valid, invalid_idx = armor.audit.verify_log_integrity()
        return JSONResponse(
            content={"is_valid": is_valid, "first_invalid_index": invalid_idx}
        )

    return app
