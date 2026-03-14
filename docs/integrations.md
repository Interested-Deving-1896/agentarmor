# AgentArmor Integrations Guide

AgentArmor ships with four framework integrations and two standalone security guards.
All integrations are available via `from agentarmor.integrations.<name> import ...`
or directly from the top-level `agentarmor` package.

---

## OpenClaw Identity Guard

**Module:** `agentarmor.integrations.openclaw`
**Import:** `from agentarmor import OpenClawGuard`

OpenClaw stores agent personality files (SOUL.md, MEMORY.md, USER.md, etc.) as
plaintext markdown. Any malware or unauthorized process on the host can read and
steal the agent's identity. OpenClawGuard encrypts these files with AES-256-GCM
and verifies integrity with BLAKE3.

### Supported Identity Files

| File | Description |
|------|-------------|
| `SOUL.md` | Agent personality and core directive |
| `MEMORY.md` | Persistent agent memory |
| `USER.md` | User preferences and context |
| `NOTES.md` | Agent working notes |
| `PERSONA.md` | Persona definition |
| `CONTEXT.md` | Environmental context |
| `PROFILE.md` | Agent profile metadata |

### Usage

```python
from agentarmor import OpenClawGuard

# Point to your OpenClaw identity directory
guard = OpenClawGuard(identity_dir="~/.openclaw")

# 1. SCAN — read-only audit, no files modified
report = guard.scan()
print(report["risk_level"])       # "high" | "low" | "unknown"
print(report["plaintext_files"])  # ["SOUL.md", "MEMORY.md"]
print(report["encrypted_files"])  # ["SOUL.md.armor"]

# 2. ENCRYPT — AES-256-GCM, plaintext deleted after encryption
enc_report = guard.encrypt_identity_files()
print(enc_report.summary())
# Identity directory: /home/user/.openclaw
# Encrypted now:      ['SOUL.md', 'MEMORY.md']
# Already secured:    ['USER.md']
# Failed:             []

assert enc_report.success  # True if no failures

# 3. DECRYPT — restore plaintext for debugging
dec_report = guard.decrypt_identity_files()
print(dec_report.decrypted)  # ['SOUL.md', 'MEMORY.md']
```

### Encryption Details

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key source:** `AGENTARMOR_ENCRYPTION_KEY` env var (hex), or auto-derived from machine identity
- **Output:** `<filename>.armor` (encrypted) + `<filename>.armor.meta.json` (integrity hash, metadata)
- **Integrity:** BLAKE3 hash stored in sidecar JSON for tamper detection

### Auto-detection

If no `identity_dir` is provided, OpenClawGuard searches these locations in order:
1. `~/.openclaw`
2. `~/.config/openclaw`
3. `~/AppData/Roaming/openclaw` (Windows)
4. `/etc/openclaw`

---

## MCP Server Scanner

**Module:** `agentarmor.integrations.mcp`
**Import:** `from agentarmor import MCPGuard, MCPScanReport`

Scans MCP (Model Context Protocol) servers for security risks **before** your agent
connects. Detects dangerous tools, insecure transport, missing auth, and rug-pull
patterns (tools that claim to be safe but have dangerous capabilities).

### Risk Levels

| Level | Meaning |
|-------|---------|
| `LOW` | All checks passed — server appears safe |
| `MEDIUM` | Minor concerns (missing auth, file write tools) |
| `HIGH` | Serious risks (no HTTPS, privilege escalation tools) |
| `CRITICAL` | Dangerous (shell execution, rug-pull detected) |
| `UNKNOWN` | Could not assess (no manifest, server unreachable) |

### Usage

```python
from agentarmor import MCPGuard, MCPScanReport
from agentarmor.integrations.mcp import RiskLevel

guard = MCPGuard()

# --- Scan a live server ---
report = guard.scan_server("http://localhost:8000")
print(report.summary())
# Server:          http://localhost:8000
# Risk level:      HIGH
# HTTPS:           ✗ INSECURE
# Auth:            ✗ NONE DETECTED
# Tools scanned:   3

if report.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
    raise SecurityError("MCP server failed security scan")

# --- Scan a tool manifest offline ---
tools = [
    {"name": "read_file", "description": "Read a file from disk"},
    {"name": "exec_command", "description": "Execute shell commands"},
    {"name": "search_web", "description": "Search the web"},
]
report = guard.scan_tool_manifest(tools)
print(report.dangerous_tools)
# [ToolRisk(tool_name='exec_command', risk_level=CRITICAL,
#           reason='Shell/command execution capability')]

# --- Rug-pull detection ---
# Catches tools that claim to be read-only but have dangerous names
tools = [{"name": "exec_data", "description": "Safe read-only lookup"}]
report = guard.scan_tool_manifest(tools)
print(report.rug_pull_indicators)
# ["'exec_data': Tool claims to be read-only but name suggests write operation"]
```

### What Gets Scanned

| Check | What It Detects |
|-------|----------------|
| **Transport** | HTTP vs HTTPS |
| **Auth** | Token/key/auth in URL |
| **Tool names** | `exec`, `shell`, `delete_all`, `sudo`, `transfer_funds`, etc. |
| **Rug-pull** | Description says "safe/read-only" but name says "exec/delete/write" |
| **Manifest fetch** | Tries `/tools`, `/.well-known/mcp/tools`, `/v1/tools`, `/api/tools` |

### Providing a Pre-fetched Manifest

```python
# If you already have the tool list (e.g., from the MCP SDK)
report = guard.scan_server(
    "https://my-server.com",
    tool_manifest=[
        {"name": "read_db", "description": "Read from database"},
        {"name": "write_file", "description": "Write to filesystem"},
    ],
    timeout=10,  # HTTP timeout in seconds
)
```

---

## LangChain Integration

**Module:** `agentarmor.integrations.langchain`
**Import:** `from agentarmor.integrations.langchain import AgentArmorCallback`

Plugs into LangChain's callback system to intercept and validate every tool call.

```python
from agentarmor import AgentArmor
from agentarmor.integrations.langchain import AgentArmorCallback

armor = AgentArmor()

# Create the callback handler
callback = AgentArmorCallback(armor=armor)

# Attach to your LangChain agent
agent.invoke(
    {"input": "Find all documents about Q4 revenue"},
    config={"callbacks": [callback]},
)
```

The callback intercepts `on_tool_start` events, runs them through AgentArmor's
8-layer pipeline, and blocks the tool call if any layer returns DENY.

---

## OpenAI Integration

**Module:** `agentarmor.integrations.openai`
**Import:** `from agentarmor.integrations.openai import secure_openai_client`

Wraps the OpenAI client to validate all API calls through AgentArmor.

```python
from openai import OpenAI
from agentarmor import AgentArmor
from agentarmor.integrations.openai import secure_openai_client

armor = AgentArmor()
client = secure_openai_client(OpenAI(), armor=armor)

# Use the client normally — AgentArmor validates every call
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

---

## Writing Custom Integrations

All integrations follow the same pattern:

1. **Intercept** — capture the event (tool call, API request, message)
2. **Wrap** — convert it to an `AgentEvent`
3. **Process** — send through `armor.process(event)` or `armor.intercept(...)`
4. **Act** — block, allow, or escalate based on the `PipelineResult`

```python
from agentarmor import AgentArmor, AgentEvent

armor = AgentArmor()

# Your custom integration
async def my_integration(tool_name: str, args: dict) -> bool:
    event = AgentEvent(
        agent_id="my-agent",
        event_type="tool_call",
        action=tool_name,
        params=args,
    )
    result = await armor.process(event)
    return result.is_safe
```

See the [Architecture doc](architecture.md) for extension points and the
[source code](../src/agentarmor/integrations/) for reference implementations.
