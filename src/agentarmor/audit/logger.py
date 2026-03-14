"""Audit & Observability — tamper-proof logging, OpenTelemetry tracing."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import blake3
import structlog

from agentarmor.core.config import AuditConfig
from agentarmor.core.types import AgentEvent, LayerResult, PipelineResult

logger = structlog.get_logger("agentarmor.audit")


class TamperProofLog:
    """Append-only log with BLAKE3 hash chaining for tamper detection."""

    def __init__(self, log_file: str | Path | None = None):
        self._entries: list[dict[str, Any]] = []
        self._prev_hash: str = "0" * 64  # Genesis hash
        self._log_file = Path(log_file) if log_file else None
        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: dict[str, Any]) -> str:
        """Append an entry to the log. Returns the entry hash."""
        entry["_seq"] = len(self._entries)
        entry["_timestamp"] = time.time()
        entry["_prev_hash"] = self._prev_hash

        payload = json.dumps(entry, sort_keys=True, default=str)
        entry_hash = blake3.blake3(payload.encode()).hexdigest()
        entry["_hash"] = entry_hash

        self._entries.append(entry)
        self._prev_hash = entry_hash

        if self._log_file:
            with open(self._log_file, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")

        return entry_hash

    def verify_integrity(self) -> tuple[bool, int]:
        """Verify the entire log chain. Returns (is_valid, first_invalid_index)."""
        prev_hash = "0" * 64
        for i, entry in enumerate(self._entries):
            if entry.get("_prev_hash") != prev_hash:
                return False, i
            stored_hash = entry.pop("_hash", "")
            payload = json.dumps(entry, sort_keys=True, default=str)
            computed = blake3.blake3(payload.encode()).hexdigest()
            entry["_hash"] = stored_hash
            if computed != stored_hash:
                return False, i
            prev_hash = stored_hash
        return True, -1

    def get_entries(self, start: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        return self._entries[start:start + limit]

    @property
    def size(self) -> int:
        return len(self._entries)


class AuditLogger:
    """Main audit logger with structured logging and OpenTelemetry integration."""

    def __init__(self, config: AuditConfig | None = None, log_file: str | Path | None = None):
        self.config = config or AuditConfig()
        self._tamper_log = TamperProofLog(log_file=log_file) if self.config.tamper_proof else None
        self._tracer = None
        if self.config.otel_enabled:
            self._init_otel()

    def _init_otel(self) -> None:
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

            provider = TracerProvider()
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer("agentarmor")
        except ImportError:
            logger.warning("OpenTelemetry not available — tracing disabled")

    def log_event(self, event: AgentEvent) -> None:
        """Log an agent event."""
        entry = {
            "type": "event",
            "event_id": event.event_id,
            "agent_id": event.agent_id,
            "session_id": event.session_id,
            "event_type": event.event_type,
            "action": event.action,
            "layer": event.layer,
        }
        if self.config.log_all_events:
            entry["params"] = event.params
            entry["context"] = event.context

        logger.info("agent_event", **entry)
        if self._tamper_log:
            self._tamper_log.append(entry)

    def log_layer_result(self, event: AgentEvent, result: LayerResult) -> None:
        """Log the result of a security layer check."""
        entry = {
            "type": "layer_result",
            "event_id": event.event_id,
            "agent_id": event.agent_id,
            "layer": result.layer,
            "verdict": result.verdict.value,
            "threat_level": result.threat_level.value,
            "message": result.message,
            "processing_time_ms": result.processing_time_ms,
        }
        if result.is_blocked:
            logger.warning("security_blocked", **entry)
        elif result.needs_approval:
            logger.info("approval_required", **entry)
        else:
            logger.debug("layer_passed", **entry)

        if self._tamper_log:
            self._tamper_log.append(entry)

    def log_pipeline_result(self, result: PipelineResult) -> None:
        """Log the final pipeline result."""
        entry = {
            "type": "pipeline_result",
            "event_id": result.event.event_id,
            "agent_id": result.event.agent_id,
            "final_verdict": result.final_verdict.value,
            "final_threat_level": result.final_threat_level.value,
            "blocked_by": result.blocked_by,
            "total_processing_time_ms": result.total_processing_time_ms,
            "layers_checked": len(result.layer_results),
        }
        if result.is_safe:
            logger.info("pipeline_passed", **entry)
        else:
            logger.warning("pipeline_blocked", **entry)

        if self._tamper_log:
            self._tamper_log.append(entry)

    def verify_log_integrity(self) -> tuple[bool, int]:
        if self._tamper_log:
            return self._tamper_log.verify_integrity()
        return True, -1

    def get_audit_trail(self, agent_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if not self._tamper_log:
            return []
        entries = self._tamper_log.get_entries(limit=self._tamper_log.size)
        if agent_id:
            entries = [e for e in entries if e.get("agent_id") == agent_id]
        return entries[-limit:]
