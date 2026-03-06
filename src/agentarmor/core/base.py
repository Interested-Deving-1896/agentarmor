"""Base class for all security layers."""
from __future__ import annotations
import time
from abc import ABC, abstractmethod
from agentarmor.core.types import AgentEvent, LayerResult, SecurityVerdict, ThreatLevel


class SecurityLayer(ABC):
    name: str = "base"

    @abstractmethod
    async def process(self, event: AgentEvent) -> LayerResult:
        ...

    async def execute(self, event: AgentEvent) -> LayerResult:
        start = time.perf_counter()
        try:
            result = await self.process(event)
        except Exception as e:
            result = LayerResult(
                layer=self.name,
                verdict=SecurityVerdict.DENY,
                threat_level=ThreatLevel.HIGH,
                message=f"Layer error: {e}",
                details={"error": str(e), "error_type": type(e).__name__},
            )
        result.processing_time_ms = (time.perf_counter() - start) * 1000
        return result
