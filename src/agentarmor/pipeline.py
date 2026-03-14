"""Main AgentArmor pipeline — orchestrates all 8 security layers."""

from __future__ import annotations

import functools
import time
from collections.abc import Callable
from typing import Any

from agentarmor.audit.logger import AuditLogger
from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import ArmorConfig
from agentarmor.core.exceptions import PolicyViolationError
from agentarmor.core.types import (
    AgentEvent,
    LayerResult,
    PipelineResult,
    SecurityVerdict,
    ThreatLevel,
)
from agentarmor.layers.context.assembler import ContextLayer
from agentarmor.layers.execution.sandbox import ExecutionLayer
from agentarmor.layers.identity.manager import IdentityLayer
from agentarmor.layers.ingestion.scanner import IngestionLayer
from agentarmor.layers.interagent.trust import InterAgentLayer
from agentarmor.layers.output.filter import OutputLayer
from agentarmor.layers.planning.validator import PlanningLayer
from agentarmor.layers.storage.encryption import StorageLayer
from agentarmor.policy.engine import PolicyEngine, SecurityPolicy


class AgentArmor:
    """Main AgentArmor class — the single entry point for all security operations.

    Usage:
        armor = AgentArmor(config=ArmorConfig.from_yaml("config.yaml"))
        result = await armor.process(event)

        # Or as a decorator:
        @armor.shield
        async def my_tool(query: str) -> str:
            ...
    """

    def __init__(
        self,
        config: ArmorConfig | None = None,
        policy: SecurityPolicy | None = None,
        audit_log_file: str | None = None,
    ):
        self.config = config or ArmorConfig()
        self.policy_engine = PolicyEngine(policy=policy)
        self.audit = AuditLogger(config=self.config.audit, log_file=audit_log_file)

        # Initialize all layers
        self.l1_ingestion = IngestionLayer(config=self.config.ingestion)
        self.l2_storage = StorageLayer(config=self.config.storage)
        self.l3_context = ContextLayer(config=self.config.context)
        self.l4_planning = PlanningLayer(config=self.config.planning)
        self.l5_execution = ExecutionLayer(config=self.config.execution)
        self.l6_output = OutputLayer(config=self.config.output)
        self.l7_interagent = InterAgentLayer(config=self.config.interagent)
        self.l8_identity = IdentityLayer(config=self.config.identity)

        # Ordered pipeline (identity first, then data flow)
        self._pipeline: list[SecurityLayer] = [
            self.l8_identity,
            self.l1_ingestion,
            self.l2_storage,
            self.l3_context,
            self.l4_planning,
            self.l5_execution,
            self.l7_interagent,
        ]
        # Output layer runs separately on results
        self._output_layer = self.l6_output

    async def process(self, event: AgentEvent) -> PipelineResult:
        """Run an agent event through the full security pipeline."""
        start = time.perf_counter()
        self.audit.log_event(event)

        pipeline_result = PipelineResult(event=event)

        # Policy engine pre-check
        policy_verdict, policy_reason = self.policy_engine.evaluate(event)
        if policy_verdict == SecurityVerdict.DENY:
            pipeline_result.final_verdict = SecurityVerdict.DENY
            pipeline_result.final_threat_level = ThreatLevel.HIGH
            pipeline_result.blocked_by = "policy_engine"
            pipeline_result.layer_results.append(LayerResult(
                layer="policy_engine", verdict=SecurityVerdict.DENY,
                threat_level=ThreatLevel.HIGH, message=policy_reason,
            ))
            pipeline_result.total_processing_time_ms = (time.perf_counter() - start) * 1000
            self.audit.log_pipeline_result(pipeline_result)
            return pipeline_result

        # Run through each layer
        for layer in self._pipeline:
            result = await layer.execute(event)
            pipeline_result.layer_results.append(result)
            self.audit.log_layer_result(event, result)

            if result.is_blocked:
                pipeline_result.final_verdict = SecurityVerdict.DENY
                pipeline_result.final_threat_level = result.threat_level
                pipeline_result.blocked_by = layer.name
                pipeline_result.total_processing_time_ms = (time.perf_counter() - start) * 1000
                self.audit.log_pipeline_result(pipeline_result)
                return pipeline_result

            if result.needs_approval:
                pipeline_result.final_verdict = SecurityVerdict.ESCALATE
                pipeline_result.final_threat_level = result.threat_level
                pipeline_result.blocked_by = layer.name
                pipeline_result.total_processing_time_ms = (time.perf_counter() - start) * 1000
                self.audit.log_pipeline_result(pipeline_result)
                return pipeline_result

        pipeline_result.final_verdict = policy_verdict
        pipeline_result.total_processing_time_ms = (time.perf_counter() - start) * 1000
        self.audit.log_pipeline_result(pipeline_result)
        return pipeline_result

    async def scan_output(self, event: AgentEvent) -> LayerResult:
        """Run only the output layer on an event (for post-generation scanning)."""
        result = await self._output_layer.execute(event)
        self.audit.log_layer_result(event, result)
        return result

    async def intercept(
        self,
        action: str,
        params: dict[str, Any] | None = None,
        agent_id: str = "default",
        context: dict[str, Any] | None = None,
        input_data: Any = None,
        output_data: Any = None,
    ) -> PipelineResult:
        """Convenience method to create an event and process it."""
        event = AgentEvent(
            agent_id=agent_id,
            event_type="tool_call",
            action=action,
            params=params or {},
            context=context or {},
            input_data=input_data,
            output_data=output_data,
        )
        return await self.process(event)

    def shield(self, func: Callable | None = None, *, action: str = ""):
        """Decorator to wrap any async function with AgentArmor security.

        Usage:
            @armor.shield
            async def dangerous_tool(query: str) -> str:
                ...

            @armor.shield(action="database.query")
            async def db_query(sql: str) -> dict:
                ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                act = action or f"{fn.__module__}.{fn.__qualname__}"
                event = AgentEvent(
                    agent_id=kwargs.pop("_agent_id", "default"),
                    event_type="tool_call",
                    action=act,
                    params=kwargs,
                    input_data=args[0] if args else None,
                )
                result = await self.process(event)
                if not result.is_safe:
                    raise PolicyViolationError(
                        layer=result.blocked_by or "unknown",
                        action=act,
                        reason=result.layer_results[-1].message if result.layer_results else "Blocked",
                    )
                return await fn(*args, **kwargs)
            return wrapper

        if func is not None:
            return decorator(func)
        return decorator
