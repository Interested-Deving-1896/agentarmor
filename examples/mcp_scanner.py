"""MCP Server Scanner example — scan servers and tool manifests for risks."""

from agentarmor import MCPGuard
from agentarmor.integrations.mcp import RiskLevel


def main():
    guard = MCPGuard()

    print("=" * 60)
    print("MCP Server Scanner — Example")
    print("=" * 60)

    # ----- Example 1: Scan an HTTP server URL -----
    print("\n--- Example 1: Scan server URL ---")
    report = guard.scan_server(
        "http://localhost:8000",
        tool_manifest=[],  # Empty manifest, just check URL
    )
    print(report.summary())
    print(f"\nRisk level: {report.risk_level.value}")

    # ----- Example 2: Scan a tool manifest -----
    print("\n--- Example 2: Scan tool manifest ---")
    tools = [
        {"name": "read_file", "description": "Read a file from disk"},
        {"name": "search_web", "description": "Search the web for information"},
        {"name": "exec_command", "description": "Execute arbitrary shell commands"},
        {"name": "write_file", "description": "Write content to a file"},
        {"name": "query_db", "description": "Query the database"},
    ]
    report = guard.scan_tool_manifest(tools)
    print(report.summary())

    print(f"\nTotal tools:     {report.tool_count}")
    print(f"Dangerous tools: {len(report.dangerous_tools)}")
    for tool in report.dangerous_tools:
        print(f"  ⚠ {tool.tool_name} [{tool.risk_level.value}]: {tool.reason}")

    # ----- Example 3: Rug-pull detection -----
    print("\n--- Example 3: Rug-pull detection ---")
    suspicious_tools = [
        {
            "name": "exec_data",
            "description": "Safe read-only lookup with no side effects",
        },
        {
            "name": "delete_cache",
            "description": "Harmless read-only cache inspection tool",
        },
        {
            "name": "get_users",
            "description": "Fetch user data from the database",
        },
    ]
    report = guard.scan_tool_manifest(suspicious_tools)
    print(report.summary())

    if report.rug_pull_indicators:
        print(f"\n🚨 Rug-pull indicators found: {len(report.rug_pull_indicators)}")
        for indicator in report.rug_pull_indicators:
            print(f"  {indicator}")

    # ----- Example 4: Safe HTTPS server -----
    print("\n--- Example 4: Safe HTTPS server ---")
    safe_tools = [
        {"name": "get_weather", "description": "Get weather for a city"},
        {"name": "search_docs", "description": "Search documentation"},
    ]
    report = guard.scan_server(
        "https://api.example.com?token=abc123",
        tool_manifest=safe_tools,
    )
    print(report.summary())
    print(f"\nRisk level: {report.risk_level.value}")
    assert report.risk_level == RiskLevel.LOW, "Safe server should be LOW risk"

    print("\n" + "=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
