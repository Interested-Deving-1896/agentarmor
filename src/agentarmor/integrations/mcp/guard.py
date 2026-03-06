"""MCP integration — security guard for Model Context Protocol servers."""

from __future__ import annotations

import asyncio
from typing import Any

from agentarmor.core.types import AgentEvent


class MCPGuard:
    """Wraps MCP tool calls with AgentArmor security checks.

    Usage:
        from agentarmor import AgentArmor
        from agentarmor.integrations.mcp import MCPGuard

        armor = AgentArmor()
        guard = MCPGuard(armor=armor)

        # Wrap an MCP tool call
        result = await guard.call_tool(
            server="my-mcp-server",
            tool="read_file",
            arguments={"path": "/etc/passwd"},
        )
    """

    def __init__(self, armor: Any, agent_id: str = "mcp-agent"):
        self._armor = armor
        self._agent_id = agent_id

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Intercept an MCP tool call and run security checks."""
        event = AgentEvent(
            agent_id=self._agent_id,
            event_type="mcp_tool_call",
            action=f"mcp.{server}.{tool}",
            params=arguments or {},
            context=context or {},
            metadata={"mcp_server": server, "mcp_tool": tool},
        )

        result = await self._armor.process(event)

        return {
            "allowed": result.is_safe,
            "verdict": result.final_verdict.value,
            "blocked_by": result.blocked_by,
            "message": result.layer_results[-1].message if result.layer_results else "",
        }

    async def validate_server(self, server_config: dict[str, Any]) -> dict[str, Any]:
        """Validate an MCP server configuration for security issues."""
        findings = []

        # Check for suspicious tool names
        tools = server_config.get("tools", [])
        dangerous_tools = {"exec", "shell", "eval", "system", "subprocess", "os_command"}
        for tool in tools:
            name = tool.get("name", "").lower()
            if any(d in name for d in dangerous_tools):
                findings.append(f"Dangerous tool detected: {tool.get('name')}")

        # Check for over-broad permissions
        if server_config.get("allow_all_tools", False):
            findings.append("Server allows all tools without restriction")

        # Check transport security
        transport = server_config.get("transport", {})
        if transport.get("type") == "http" and not transport.get("url", "").startswith("https"):
            findings.append("MCP server uses unencrypted HTTP transport")

        return {
            "is_safe": len(findings) == 0,
            "findings": findings,
        }
