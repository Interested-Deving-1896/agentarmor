"""
AgentArmor v0.3.0 — Full MCP Security Scan Demo

Demonstrates TLS validation + OAuth 2.1 check + tool manifest scanning
on a real or local MCP server.
"""
from agentarmor.integrations.mcp import MCPGuard, OAuthVerifier

guard = MCPGuard()

# --- Demo 1: HTTP server (will fail TLS + OAuth checks) ---
print("\n=== Demo 1: HTTP (insecure) server ===")
result = guard.full_security_scan(
    "http://localhost:8000",
    tool_manifest=[
        {"name": "search_web", "description": "Search the internet"},
        {"name": "exec_command", "description": "Execute shell commands"},
    ]
)
print(f"Overall risk: {result['overall_risk'].upper()}")
print(f"Passed: {result['passed']}")
print(f"Issues ({len(result['issues'])}):")
for issue in result["issues"][:5]:
    print(f"  • {issue}")

# --- Demo 2: PKCE pair generation ---
print("\n=== Demo 2: PKCE S256 pair generation ===")
verifier, challenge = OAuthVerifier.generate_pkce_pair()
print(f"code_verifier:  {verifier[:20]}...")
print(f"code_challenge: {challenge[:20]}...")
print("Use code_verifier in token request, code_challenge in auth request.")

# --- Demo 3: Tool manifest scan only ---
print("\n=== Demo 3: Tool manifest analysis ===")
tools = [
    {"name": "search_files", "description": "Read-only file search with no side effects"},
    {"name": "exec_search", "description": "Execute a safe search query"},  # rug pull
    {"name": "database_query", "description": "Read-only SQL SELECT queries"},
    {"name": "shell_run", "description": "Run arbitrary shell commands"},
]
report = guard.scan_tool_manifest(tools)
print(f"Tools scanned: {report.tool_count}")
print(f"Risk level: {report.risk_level.value.upper()}")
if report.dangerous_tools:
    print("Dangerous tools:")
    for t in report.dangerous_tools:
        print(f"  ⚠ {t.tool_name} ({t.risk_level.value}): {t.reason}")
if report.rug_pull_indicators:
    print("Rug pull indicators:")
    for r in report.rug_pull_indicators:
        print(f"  🚨 {r}")
