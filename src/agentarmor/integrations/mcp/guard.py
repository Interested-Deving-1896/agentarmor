"""
AgentArmor — MCP Server Security Guard

Scans MCP (Model Context Protocol) servers for security risks before
an agent connects. Detects: dangerous tool names, HTTP (not HTTPS),
missing auth, known-malicious tool description patterns, and rug-pull
indicators (tools that claim to be safe but have dangerous descriptions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlparse


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class ToolRisk:
    tool_name: str
    risk_level: RiskLevel
    reason: str


@dataclass
class MCPScanReport:
    server_url: str
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    transport_secure: bool = False
    has_auth: bool = False
    dangerous_tools: list[ToolRisk] = field(default_factory=list)
    rug_pull_indicators: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tool_count: int = 0
    scanned: bool = False
    error: str | None = None

    def summary(self) -> str:
        lines = [
            f"Server:          {self.server_url}",
            f"Risk level:      {self.risk_level.value.upper()}",
            f"HTTPS:           {'✓' if self.transport_secure else '✗ INSECURE'}",
            f"Auth:            {'✓' if self.has_auth else '✗ NONE DETECTED'}",
            f"Tools scanned:   {self.tool_count}",
        ]
        if self.dangerous_tools:
            lines.append("Dangerous tools:")
            for t in self.dangerous_tools:
                lines.append(f"  ⚠ {t.tool_name} ({t.risk_level.value}): {t.reason}")
        if self.rug_pull_indicators:
            lines.append("Rug pull indicators:")
            for r in self.rug_pull_indicators:
                lines.append(f"  🚨 {r}")
        if self.warnings:
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  • {w}")
        return "\n".join(lines)


class MCPGuard:
    """
    Scans MCP servers for security vulnerabilities before an agent connects.

    Usage:
        from agentarmor.integrations.mcp import MCPGuard
        guard = MCPGuard()
        report = guard.scan_server("http://localhost:8000")
        print(report.summary())
        if report.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            raise SecurityError("MCP server failed security scan")
    """

    # Tool names that indicate dangerous capabilities
    DANGEROUS_TOOL_PATTERNS = [
        (r"exec|execute|run_command|shell|bash|cmd|powershell", RiskLevel.CRITICAL,
         "Shell/command execution capability"),
        (r"delete_all|drop_table|truncate|wipe|destroy|format_disk", RiskLevel.CRITICAL,
         "Bulk destructive operation"),
        (r"exfil|steal|harvest|scrape_credentials|dump_secrets", RiskLevel.CRITICAL,
         "Data exfiltration pattern"),
        (r"sudo|admin|root|elevate|privilege", RiskLevel.HIGH,
         "Privilege escalation pattern"),
        (r"send_email|smtp|mass_mail|bulk_send", RiskLevel.HIGH,
         "Mass communication capability"),
        (r"transfer_funds|wire|payment|charge_card", RiskLevel.HIGH,
         "Financial transaction capability"),
        (r"write_file|create_file|upload|deploy", RiskLevel.MEDIUM,
         "File write capability"),
        (r"database|sql|query|db_write", RiskLevel.MEDIUM,
         "Database write capability"),
    ]

    # Rug pull: description says one thing, name says another
    RUG_PULL_PATTERNS = [
        (r"safe|harmless|read.?only|no.?side.?effects", r"exec|delete|write|send|modify",
         "Tool claims to be read-only but name suggests write operation"),
        (r"search|lookup|find|query", r"exec|shell|run|command",
         "Tool claims to search but executes commands"),
        (r"read|fetch|get|retrieve", r"delete|drop|remove|truncate",
         "Tool claims to read but may delete"),
    ]

    def scan_server(self, server_url: str,
                    tool_manifest: list[dict] | None = None,
                    timeout: int = 5) -> MCPScanReport:
        """
        Scan an MCP server. Performs:
        1. Static URL analysis (HTTPS, auth indicators)
        2. Tool manifest analysis (if provided or fetchable)
        3. Rug pull detection

        Args:
            server_url: The MCP server URL to scan
            tool_manifest: Optional pre-fetched list of tool dicts
                           Each dict: {"name": str, "description": str}
            timeout: HTTP request timeout in seconds
        """
        report = MCPScanReport(server_url=server_url)

        # 1. Transport security
        parsed = urlparse(server_url)
        report.transport_secure = parsed.scheme == "https"
        if not report.transport_secure:
            report.warnings.append(
                "HTTP transport is unencrypted — tool calls and responses "
                "are visible to network observers"
            )

        # 2. Auth detection (heuristic from URL)
        has_token = any(k in server_url.lower() for k in ["token=", "key=", "auth=", "bearer"])
        report.has_auth = has_token
        if not has_token:
            report.warnings.append(
                "No authentication token detected in URL — "
                "server may be unauthenticated"
            )

        # 3. Try to fetch tool manifest if not provided
        if tool_manifest is None:
            tool_manifest = self._fetch_tool_manifest(server_url, timeout)

        # 4. Scan tools
        if tool_manifest:
            report.tool_count = len(tool_manifest)
            report.scanned = True
            for tool in tool_manifest:
                name = tool.get("name", "")
                description = tool.get("description", "")
                risk = self._score_tool(name, description)
                if risk:
                    report.dangerous_tools.append(risk)
                rug_pull = self._detect_rug_pull(name, description)
                if rug_pull:
                    report.rug_pull_indicators.append(rug_pull)
        else:
            report.warnings.append(
                "Could not fetch tool manifest — static analysis only"
            )

        # 5. Compute overall risk
        report.risk_level = self._compute_risk_level(report)
        return report

    def scan_tool_manifest(self, tools: list[dict]) -> MCPScanReport:
        """Scan a pre-fetched tool manifest without making HTTP requests."""
        report = MCPScanReport(server_url="local-manifest")
        report.tool_count = len(tools)
        report.scanned = True

        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            risk = self._score_tool(name, description)
            if risk:
                report.dangerous_tools.append(risk)
            rug_pull = self._detect_rug_pull(name, description)
            if rug_pull:
                report.rug_pull_indicators.append(rug_pull)

        report.risk_level = self._compute_risk_level(report)
        return report

    def _fetch_tool_manifest(self, url: str, timeout: int) -> list[dict] | None:
        """Try to fetch /tools or /.well-known/mcp/tools from the server."""
        try:
            import httpx
            endpoints = ["/tools", "/.well-known/mcp/tools", "/v1/tools", "/api/tools"]
            base = url.rstrip("/")
            for endpoint in endpoints:
                try:
                    resp = httpx.get(f"{base}{endpoint}", timeout=timeout)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list):
                            return data
                        if isinstance(data, dict) and "tools" in data:
                            return data["tools"]
                except Exception:
                    continue
        except ImportError:
            pass
        return None

    def _score_tool(self, name: str, description: str) -> ToolRisk | None:
        combined = f"{name} {description}".lower()
        for pattern, level, reason in self.DANGEROUS_TOOL_PATTERNS:
            if re.search(pattern, combined):
                return ToolRisk(tool_name=name, risk_level=level, reason=reason)
        return None

    def _detect_rug_pull(self, name: str, description: str) -> str | None:
        desc_lower = description.lower()
        name_lower = name.lower()
        for safe_pattern, dangerous_pattern, message in self.RUG_PULL_PATTERNS:
            if re.search(safe_pattern, desc_lower) and re.search(dangerous_pattern, name_lower):
                return f"'{name}': {message}"
        return None

    def _compute_risk_level(self, report: MCPScanReport) -> RiskLevel:
        if report.rug_pull_indicators:
            return RiskLevel.CRITICAL
        critical_tools = [t for t in report.dangerous_tools if t.risk_level == RiskLevel.CRITICAL]
        if critical_tools:
            return RiskLevel.CRITICAL
        high_tools = [t for t in report.dangerous_tools if t.risk_level == RiskLevel.HIGH]
        if high_tools or not report.transport_secure:
            return RiskLevel.HIGH
        if report.dangerous_tools or not report.has_auth:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
