"""LangChain integration — callback handler for automatic security scanning."""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

from agentarmor.core.types import AgentEvent


class AgentArmorCallback:
    """LangChain callback handler that runs AgentArmor checks on every tool call.

    Usage:
        from agentarmor.integrations.langchain import AgentArmorCallback
        from agentarmor import AgentArmor

        armor = AgentArmor()
        callback = AgentArmorCallback(armor=armor, agent_id="my-agent")

        # Pass to LangChain
        agent.invoke({"input": "..."}, config={"callbacks": [callback]})
    """

    def __init__(self, armor: Any, agent_id: str = "langchain-agent"):
        self._armor = armor
        self._agent_id = agent_id

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Intercept tool calls before execution."""
        tool_name = serialized.get("name", "unknown_tool")
        event = AgentEvent(
            agent_id=self._agent_id,
            event_type="tool_call",
            action=f"langchain.tool.{tool_name}",
            params=inputs or {},
            input_data=input_str,
            metadata=metadata or {},
        )
        result = asyncio.get_event_loop().run_until_complete(self._armor.process(event))
        if not result.is_safe:
            from agentarmor.core.exceptions import PolicyViolationError
            raise PolicyViolationError(
                layer=result.blocked_by or "unknown",
                action=tool_name,
                reason=result.layer_results[-1].message if result.layer_results else "Blocked",
            )

    def on_tool_end(
        self, output: str, *, run_id: UUID, parent_run_id: UUID | None = None, **kwargs: Any,
    ) -> None:
        """Scan tool output for PII and sensitive data."""
        event = AgentEvent(
            agent_id=self._agent_id,
            event_type="tool_output",
            action="langchain.tool.output",
            output_data=output,
        )
        asyncio.get_event_loop().run_until_complete(self._armor.scan_output(event))
        # If PII is found, we could modify the output here
