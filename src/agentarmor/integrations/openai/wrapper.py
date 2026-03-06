"""OpenAI integration — wraps the OpenAI client with AgentArmor security."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agentarmor.core.types import AgentEvent


def secure_openai_client(client: Any, armor: Any, agent_id: str = "openai-agent") -> Any:
    """Wrap an OpenAI client with AgentArmor security.

    Usage:
        from openai import OpenAI
        from agentarmor import AgentArmor
        from agentarmor.integrations.openai import secure_openai_client

        armor = AgentArmor()
        client = secure_openai_client(OpenAI(), armor=armor)
        # Now all calls go through AgentArmor
    """
    original_create = client.chat.completions.create

    def secured_create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        tools = kwargs.get("tools", [])

        # Scan input messages
        event = AgentEvent(
            agent_id=agent_id,
            event_type="llm_request",
            action="openai.chat.completions.create",
            input_data=messages,
            params={"model": kwargs.get("model", ""), "tools": [t.get("function", {}).get("name", "") for t in tools]},
        )
        result = asyncio.get_event_loop().run_until_complete(armor.process(event))
        if not result.is_safe:
            from agentarmor.core.exceptions import PolicyViolationError
            raise PolicyViolationError(
                layer=result.blocked_by or "unknown",
                action="openai.chat.completions.create",
                reason=result.layer_results[-1].message if result.layer_results else "Blocked",
            )

        # Make the actual call
        response = original_create(*args, **kwargs)

        # Scan output
        if hasattr(response, "choices") and response.choices:
            content = response.choices[0].message.content or ""
            output_event = AgentEvent(
                agent_id=agent_id,
                event_type="llm_response",
                action="openai.chat.completions.output",
                output_data=content,
            )
            output_result = asyncio.get_event_loop().run_until_complete(armor.scan_output(output_event))
            # Could modify response here if PII detected

        return response

    client.chat.completions.create = secured_create
    return client
