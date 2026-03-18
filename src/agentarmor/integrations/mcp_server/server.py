"""
AgentArmor MCP Server — v0.4.0

Exposes AgentArmor's 8-layer security pipeline as MCP tools so that
any MCP-compatible coding agent (Claude Code, OpenClaw, Cursor with MCP,
etc.) can call AgentArmor directly without writing Python code.

Available tools:
  armor_register_agent   — Register an agent with permissions
  armor_scan_input       — Scan text for prompt injection / threats
  armor_intercept        — Run a tool call through the full 8-layer pipeline
  armor_scan_output      — Redact PII and sensitive data from agent output
  armor_scan_mcp_server  — Full security scan of an MCP server
  armor_get_status       — Health check + registered agent count

Setup for Claude Code (~/.claude/claude_desktop_config.json):
  {
    "mcpServers": {
      "agentarmor": {
        "command": "uv",
        "args": ["run", "agentarmor-mcp"],
        "cwd": "/path/to/your/project"
      }
    }
  }

Setup for OpenClaw (mcp_servers section in config):
  agentarmor:
    command: uv run agentarmor-mcp
    cwd: /path/to/your/project
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

try:
    import mcp.server.stdio
    import mcp.types as types
    from mcp.server import Server
    from mcp.server.models import InitializationOptions
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from agentarmor.core.types import AgentEvent
from agentarmor.pipeline import AgentArmor

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("agentarmor-mcp")

# Single shared armor instance — initialized once, reused across all calls
_armor: AgentArmor | None = None
# Registry: agent_id -> token (in-memory for the server session)
_agents: dict[str, str] = {}


def _get_armor() -> AgentArmor:
    global _armor
    if _armor is None:
        _armor = AgentArmor()
    return _armor


def _ok(data: Any) -> list[types.TextContent]:
    """Return a successful JSON response."""
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def _err(message: str) -> list[types.TextContent]:
    """Return an error JSON response."""
    return [types.TextContent(type="text", text=json.dumps({
        "error": message,
        "success": False,
    }, indent=2))]


def create_server() -> Server:
    server = Server("agentarmor-security")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="armor_register_agent",
                description=(
                    "Register an agent with AgentArmor identity system. "
                    "Returns a credential token. Call this once before using "
                    "armor_intercept. permissions is a list of glob patterns "
                    "like ['read.*', 'database.query', 'scan.*']."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Unique identifier for this agent, e.g. 'claude-code-session-1'",
                        },
                        "permissions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "List of permitted action globs. "
                                "Examples: 'read.*', 'database.query', 'scan.*', 'search.*'"
                            ),
                            "default": ["scan.*", "read.*", "search.*"],
                        },
                        "agent_type": {
                            "type": "string",
                            "description": "Type label for logging: general, coding, research, financial",
                            "default": "general",
                        },
                    },
                    "required": ["agent_id"],
                },
            ),
            types.Tool(
                name="armor_scan_input",
                description=(
                    "Scan user input or any retrieved text for prompt injection, "
                    "jailbreaks, DAN attacks, and data exfiltration attempts. "
                    "Call this BEFORE passing any external text to your LLM. "
                    "Returns is_safe (bool), threat_level, and details if blocked."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The text to scan — user message, retrieved document, tool response, etc.",
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Your registered agent_id",
                            "default": "default",
                        },
                    },
                    "required": ["text"],
                },
            ),
            types.Tool(
                name="armor_intercept",
                description=(
                    "Run a proposed tool call through AgentArmor's full 8-layer "
                    "security pipeline BEFORE executing it. Returns verdict "
                    "(allow/deny/escalate), which layer blocked it if denied, "
                    "and the threat level. Use this before ANY tool call that "
                    "touches external systems: file reads, database queries, "
                    "API calls, shell commands, etc."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": (
                                "The action in dot notation, e.g. "
                                "'database.query', 'read.file', 'shell.exec', 'email.send'"
                            ),
                        },
                        "params": {
                            "type": "object",
                            "description": (
                                "Parameters for the action, e.g. "
                                "{'path': '/etc/passwd'} or {'query': 'SELECT *'}"
                            ),
                            "default": {},
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Your registered agent_id",
                            "default": "default",
                        },
                        "context": {
                            "type": "object",
                            "description": (
                                "Optional context metadata, e.g. "
                                "{'task': 'code review', 'user_role': 'admin'}"
                            ),
                            "default": {},
                        },
                    },
                    "required": ["action"],
                },
            ),
            types.Tool(
                name="armor_scan_output",
                description=(
                    "Scan and redact PII and sensitive data from agent output "
                    "BEFORE returning it to users or writing it to logs. "
                    "Detects and redacts: email addresses, phone numbers, SSNs, "
                    "credit card numbers, API keys, passwords, and custom patterns. "
                    "Returns the redacted text and what was found."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The agent output text to scan and redact",
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Your registered agent_id",
                            "default": "default",
                        },
                    },
                    "required": ["text"],
                },
            ),
            types.Tool(
                name="armor_scan_mcp_server",
                description=(
                    "Run a full security scan on an MCP server before connecting to it. "
                    "Checks: TLS certificate validity, OAuth 2.1 compliance, PKCE S256 "
                    "support, dangerous tool detection, rug-pull indicators, and "
                    "transport security. Returns overall_risk and a full report. "
                    "CRITICAL risk means you should NOT connect to this server."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {
                            "type": "string",
                            "description": "Full URL of the MCP server, e.g. 'https://api.example.com/mcp' or 'http://localhost:8000'",
                        },
                        "tool_manifest": {
                            "type": "array",
                            "description": "Optional pre-fetched tool list: [{'name': str, 'description': str}]",
                            "default": None,
                        },
                    },
                    "required": ["server_url"],
                },
            ),
            types.Tool(
                name="armor_get_status",
                description=(
                    "Get AgentArmor server status: version, registered agents, "
                    "layers active, and a quick health check. Use this to verify "
                    "AgentArmor is running and configured correctly."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(
        name: str, arguments: dict
    ) -> list[types.TextContent]:
        armor = _get_armor()

        # ── armor_register_agent ──────────────────────────────────────
        if name == "armor_register_agent":
            agent_id = arguments["agent_id"]
            permissions = set(arguments.get("permissions", ["scan.*", "read.*", "search.*"]))
            agent_type = arguments.get("agent_type", "general")

            try:
                identity, token = armor.l8_identity.register_agent(
                    agent_id=agent_id,
                    agent_type=agent_type,
                    permissions=permissions,
                )
                _agents[agent_id] = token
                return _ok({
                    "success": True,
                    "agent_id": agent_id,
                    "permissions": list(permissions),
                    "token_preview": token[:16] + "...",
                    "message": f"Agent '{agent_id}' registered with {len(permissions)} permissions",
                })
            except Exception as e:
                return _err(f"Registration failed: {e}")

        # ── armor_scan_input ──────────────────────────────────────────
        elif name == "armor_scan_input":
            text = arguments["text"]
            agent_id = arguments.get("agent_id", "default")

            # Auto-register default agent if needed
            if agent_id not in _agents:
                try:
                    _, token = armor.l8_identity.register_agent(
                        agent_id=agent_id,
                        permissions={"scan.*", "read.*"},
                    )
                    _agents[agent_id] = token
                except Exception:
                    pass

            event = AgentEvent(
                agent_id=agent_id,
                event_type="tool_call",
                action="scan.input",
                input_data=text,
            )
            try:
                result = await armor.l1_ingestion.execute(event)
                return _ok({
                    "is_safe": result.verdict.value == "allow",
                    "verdict": result.verdict.value,
                    "threat_level": result.threat_level.value,
                    "message": result.message,
                    "processing_time_ms": round(result.processing_time_ms, 2),
                })
            except Exception as e:
                return _err(f"Scan failed: {e}")

        # ── armor_intercept ───────────────────────────────────────────
        elif name == "armor_intercept":
            action = arguments["action"]
            params = arguments.get("params", {})
            agent_id = arguments.get("agent_id", "default")
            context = arguments.get("context", {})

            # Auto-register default agent if needed
            if agent_id not in _agents:
                try:
                    _, token = armor.l8_identity.register_agent(
                        agent_id=agent_id,
                        permissions={"scan.*", "read.*", "search.*", "database.query"},
                    )
                    _agents[agent_id] = token
                except Exception:
                    pass

            try:
                result = await armor.intercept(
                    action=action,
                    params=params,
                    agent_id=agent_id,
                    context=context,
                )
                response = {
                    "is_safe": result.is_safe,
                    "verdict": result.final_verdict.value,
                    "threat_level": result.final_threat_level.value,
                    "blocked_by": result.blocked_by,
                    "layers_checked": result.layers_checked,
                    "total_processing_time_ms": round(result.total_processing_time_ms, 2),
                    "message": (
                        result.layer_results[-1].message
                        if result.layer_results else "No details"
                    ),
                }
                if not result.is_safe:
                    response["action_required"] = (
                        "DO NOT execute this tool call. "
                        f"Blocked by {result.blocked_by}: {response['message']}"
                    )
                return _ok(response)
            except Exception as e:
                return _err(f"Intercept failed: {e}")

        # ── armor_scan_output ─────────────────────────────────────────
        elif name == "armor_scan_output":
            text = arguments["text"]
            agent_id = arguments.get("agent_id", "default")

            event = AgentEvent(
                agent_id=agent_id,
                event_type="llm_response",
                action="scan.output",
                output_data=text,
            )
            try:
                result = await armor.scan_output(event)
                redacted_text = result.modified_data or text
                was_modified = redacted_text != text
                return _ok({
                    "redacted_text": redacted_text,
                    "pii_found": was_modified,
                    "verdict": result.verdict.value,
                    "threat_level": result.threat_level.value,
                    "message": result.message,
                })
            except Exception as e:
                return _err(f"Output scan failed: {e}")

        # ── armor_scan_mcp_server ─────────────────────────────────────
        elif name == "armor_scan_mcp_server":
            server_url = arguments["server_url"]
            tool_manifest = arguments.get("tool_manifest")

            try:
                from agentarmor.integrations.mcp import MCPGuard
                guard = MCPGuard()
                result = guard.full_security_scan(
                    server_url=server_url,
                    tool_manifest=tool_manifest,
                    timeout=5,
                )
                mcp_r = result["mcp_report"]
                tls_r = result.get("tls_report")
                oauth_r = result.get("oauth_report")

                response = {
                    "overall_risk": result["overall_risk"],
                    "passed": result["passed"],
                    "issues_count": len(result["issues"]),
                    "mcp": {
                        "risk_level": mcp_r.risk_level.value,
                        "dangerous_tools": [
                            {"name": t.tool_name, "risk": t.risk_level.value, "reason": t.reason}
                            for t in mcp_r.dangerous_tools
                        ],
                        "rug_pull_indicators": mcp_r.rug_pull_indicators,
                        "transport_secure": mcp_r.transport_secure,
                    },
                }
                if tls_r:
                    response["tls"] = {
                        "valid": tls_r.valid,
                        "tls_version": tls_r.tls_version,
                        "cipher_suite": tls_r.cipher_suite,
                        "days_until_expiry": tls_r.days_until_expiry,
                        "issues": tls_r.issues,
                    }
                if oauth_r:
                    response["oauth"] = {
                        "compliant": oauth_r.oauth_compliant,
                        "pkce_s256_supported": oauth_r.pkce_s256_supported,
                        "has_protected_resource_metadata": oauth_r.has_protected_resource_metadata,
                        "issues": oauth_r.issues,
                    }
                if result["overall_risk"] == "critical":
                    response["recommendation"] = "DO NOT connect to this MCP server."
                elif result["overall_risk"] == "high":
                    response["recommendation"] = "Exercise extreme caution. Review all issues before connecting."
                else:
                    response["recommendation"] = "Server passed security scan."

                return _ok(response)
            except Exception as e:
                return _err(f"MCP scan failed: {e}")

        # ── armor_get_status ──────────────────────────────────────────
        elif name == "armor_get_status":
            import agentarmor
            return _ok({
                "status": "running",
                "version": getattr(agentarmor, "__version__", "0.4.0"),
                "registered_agents": list(_agents.keys()),
                "agent_count": len(_agents),
                "layers": {
                    "L1_ingestion": armor.l1_ingestion is not None,
                    "L2_storage": armor.l2_storage is not None,
                    "L3_context": armor.l3_context is not None,
                    "L4_planning": armor.l4_planning is not None,
                    "L5_execution": armor.l5_execution is not None,
                    "L6_output": armor.l6_output is not None,
                    "L7_interagent": armor.l7_interagent is not None,
                    "L8_identity": armor.l8_identity is not None,
                },
                "mcp_tools": [
                    "armor_register_agent",
                    "armor_scan_input",
                    "armor_intercept",
                    "armor_scan_output",
                    "armor_scan_mcp_server",
                    "armor_get_status",
                ],
            })

        else:
            return _err(f"Unknown tool: {name}")

    return server


def run() -> None:
    """Entry point for agentarmor-mcp CLI command."""
    if not MCP_AVAILABLE:
        print(
            "ERROR: mcp package not installed.\n"
            "Run: uv add --optional mcp 'mcp>=1.0'\n"
            "Then: uv sync --all-extras"
        )
        return

    async def _run():
        server = create_server()
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="agentarmor-security",
                    server_version="0.4.0",
                    capabilities=server.get_capabilities(
                        notification_options=None,
                        experimental_capabilities={},
                    ),
                ),
            )

    asyncio.run(_run())


# Allow running directly for testing
if __name__ == "__main__":
    run()
