#!/bin/bash
# AgentArmor v0.4.0 — One-command setup for Claude Code integration

set -e

echo "=== AgentArmor MCP Setup for Claude Code ==="

# 1. Install with MCP support
echo "Installing agentarmor-core[mcp]..."
pip install "agentarmor-core[mcp]" --quiet

# 2. Find Claude config location
CLAUDE_CONFIG="$HOME/.claude/claude_desktop_config.json"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
  CLAUDE_CONFIG="$APPDATA/Claude/claude_desktop_config.json"
fi

# 3. Back up existing config
if [ -f "$CLAUDE_CONFIG" ]; then
  cp "$CLAUDE_CONFIG" "${CLAUDE_CONFIG}.backup"
  echo "Backed up existing config to ${CLAUDE_CONFIG}.backup"
fi

# 4. Inject agentarmor into config
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

python3 - <<PYEOF
import json, os
config_path = "$CLAUDE_CONFIG"
script_dir = "$SCRIPT_DIR"
os.makedirs(os.path.dirname(config_path), exist_ok=True)
try:
    with open(config_path) as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    config = {}
config.setdefault("mcpServers", {})
config["mcpServers"]["agentarmor"] = {
    "command": "uv",
    "args": ["run", "agentarmor-mcp"],
    "cwd": script_dir
}
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
print(f"Updated: {config_path}")
PYEOF

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Restart Claude Code to load AgentArmor."
echo "You will see 6 new tools: armor_register_agent, armor_scan_input,"
echo "armor_intercept, armor_scan_output, armor_scan_mcp_server, armor_get_status"
echo ""
echo "Or run the proxy server instead:"
echo "  agentarmor serve --port 8400"
