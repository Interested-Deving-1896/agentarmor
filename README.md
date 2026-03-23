# 🛡️ AgentArmor

[![PyPI version](https://img.shields.io/pypi/v/agentarmor-core)](https://pypi.org/project/agentarmor-core/)
[![Python](https://img.shields.io/pypi/pyversions/agentarmor-core)](https://pypi.org/project/agentarmor-core/)
[![License](https://img.shields.io/github/license/Agastya910/agentarmor)](https://github.com/Agastya910/agentarmor/blob/main/LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/Agastya910/agentarmor/ci.yml?label=tests)](https://github.com/Agastya910/agentarmor/actions)

**Comprehensive open-source security framework for agentic AI applications.**

AgentArmor provides 8-layer defense-in-depth security for AI agents, covering every point in the data flow where data is at rest, in transit, or in use. Built to address the [OWASP Top 10 for Agentic Applications (2026)](https://owasp.org/www-project-top-10-for-agentic-security-and-integrity/).

---

## What's New in v0.4.1 — Security Fixes

- 🎯 **L4: Param-Aware Risk Scoring** — Risk scoring now considers the *target* of an action, not just the verb. `read.file /etc/shadow` correctly scores higher than `delete.file /tmp/cache.json`. See [CHANGELOG.md](CHANGELOG.md).
- ⏱️ **L7: Time-Based Trust Decay** — `TrustScorer.decay_rate` is now actually applied. Dormant agents lose trust over time: `effective_trust = stored_trust × (decay_rate ^ days_idle)`. New `get_trust_debug_info()` for analytics.

## What's New in v0.4.0

- 🚀 **MCP Server Plugin** — AgentArmor now ships as a native MCP server. Claude Code, OpenClaw, Cursor, Windsurf, and any MCP-compatible agent can call AgentArmor's security tools directly — **zero Python code required**.
- 🛠️ **6 MCP Tools** — `armor_register_agent`, `armor_scan_input`, `armor_intercept`, `armor_scan_output`, `armor_scan_mcp_server`, `armor_get_status`
- ⚡ **One-command setup** — `setup_claude_code.sh` auto-configures Claude Code with AgentArmor
- 📖 New `agentarmor-mcp` CLI entry point for stdio transport

### What's New in v0.3.0

- 🔒 **TLS Certificate Validation** — Validates MCP server TLS certificates: version, cipher suite, expiry, weak cipher detection
- 🔑 **OAuth 2.1 Compliance Checker** — Verifies OAuth 2.1 compliance with PKCE S256 support, Protected Resource Metadata, and Authorization Server Metadata
- 🛡️ **Full Security Scan** — `MCPGuard.full_security_scan()` combines TLS + OAuth + tool analysis in a single call

### What's New in v0.2.0

- 🔐 **OpenClaw Identity Guard** — Encrypts OpenClaw agent identity files with AES-256-GCM + BLAKE3 integrity
- 🔍 **MCP Server Scanner** — Scans MCP servers for dangerous tools, rug-pulls, and transport security

---

## Why AgentArmor?

Every existing security tool is a **point solution** — output validators, prompt injection scanners, or policy engines in isolation. AgentArmor is the **first unified framework** that secures the entire agentic architecture end-to-end.

## The 8 Security Layers

| Layer | Name            | What It Protects                                                          |
| ----- | --------------- | ------------------------------------------------------------------------- |
| L1    | **Ingestion**   | Input scanning, prompt injection detection, source verification           |
| L2    | **Storage**     | Encryption at rest (AES-256-GCM), data classification, integrity (BLAKE3) |
| L3    | **Context**     | Instruction-data separation, canary tokens, prompt hardening              |
| L4    | **Planning**    | Action plan validation, risk scoring, chain depth limits                  |
| L5    | **Execution**   | Rate limiting, network egress control, human approval gates               |
| L6    | **Output**      | PII redaction (Presidio), DLP, sensitivity filtering                      |
| L7    | **Inter-Agent** | Mutual auth (HMAC), trust scoring, delegation depth control               |
| L8    | **Identity**    | Agent identity, JIT permissions, credential rotation                      |

## Quick Start

### Install

```bash
# Using uv (recommended)
uv add agentarmor-core

# With MCP server support (for Claude Code, OpenClaw, etc.)
uv add "agentarmor-core[mcp]"

# With all optional features
uv add "agentarmor-core[all]"

# Available extras: proxy, pii, otel, mcp, oauth, all, dev
```

```bash
# For development
git clone https://github.com/Agastya910/agentarmor.git
cd agentarmor
uv sync --all-extras --dev
```

### Basic Usage

```python
import asyncio
from agentarmor import AgentArmor, ArmorConfig

async def main():
    armor = AgentArmor()

    # Register your agent
    identity, token = armor.l8_identity.register_agent(
        agent_id="my-agent",
        permissions={"read.*", "search.*"},
    )

    # Intercept tool calls
    result = await armor.intercept(
        action="read.file",
        params={"path": "/data/notes.txt"},
        agent_id="my-agent",
        input_data="Read the file please",
    )

    print(f"Safe: {result.is_safe}")
    print(f"Verdict: {result.final_verdict.value}")

asyncio.run(main())
```

### Use as Decorator

```python
@armor.shield(action="database.query")
async def query_database(sql: str) -> dict:
    return db.execute(sql)
```

### Proxy Server Mode

```bash
agentarmor serve --config agentarmor.yaml --port 8400
```

```bash
curl -X POST http://localhost:8400/v1/intercept \
  -H "Content-Type: application/json" \
  -d '{"action": "read.file", "agent_id": "my-agent", "input_data": "Hello"}'
```

---

## Integrations

### MCP Server — Zero-Code Security for Any Agent *(New in v0.4.0)*

AgentArmor runs as a native **MCP server** that any MCP-compatible coding agent can call directly — no Python code changes needed in your project.

**Setup for Claude Code** — add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agentarmor": {
      "command": "uv",
      "args": ["run", "agentarmor-mcp"],
      "cwd": "/path/to/your/project"
    }
  }
}
```

**Or run the one-command setup:**

```bash
bash setup_claude_code.sh
```

**Available MCP Tools:**

| Tool | What It Does |
|------|-------------|
| `armor_register_agent` | Register an agent with a permission set |
| `armor_scan_input` | Scan text for prompt injection, jailbreaks, DAN attacks |
| `armor_intercept` | Run a tool call through all 8 security layers |
| `armor_scan_output` | Redact PII (emails, SSNs, API keys) from output |
| `armor_scan_mcp_server` | Full TLS + OAuth 2.1 + rug-pull scan of any MCP server |
| `armor_get_status` | Health check: version, layers, registered agents |

> 📖 **Full setup guide:** [docs/claude_code_setup.md](docs/claude_code_setup.md)

### TLS + OAuth 2.1 Verification *(New in v0.3.0)*

```python
from agentarmor import MCPGuard

guard = MCPGuard()
result = guard.full_security_scan("https://api.example.com/mcp")
print(result["overall_risk"])  # "low" / "medium" / "high" / "critical"
```

### OpenClaw Identity Guard *(v0.2.0)*

```python
from agentarmor import OpenClawGuard
guard = OpenClawGuard(identity_dir="~/.openclaw")
enc_report = guard.encrypt_identity_files()  # AES-256-GCM + BLAKE3
```

### MCP Server Scanner *(v0.2.0)*

```python
from agentarmor import MCPGuard
guard = MCPGuard()
report = guard.scan_server("http://localhost:8000")
print(report.summary())  # Risk level, dangerous tools, rug-pulls
```

### LangChain / OpenAI

```python
# LangChain
from agentarmor.integrations.langchain import AgentArmorCallback
callback = AgentArmorCallback(armor=armor)

# OpenAI
from agentarmor.integrations.openai import secure_openai_client
client = secure_openai_client(OpenAI(), armor=armor)
```

> 📖 **Full integration guide:** [docs/integrations.md](docs/integrations.md)

---

### Red Team Testing

```python
from agentarmor.redteam import RedTeamSuite

suite = RedTeamSuite(armor=armor)
results = await suite.run_all()
suite.print_report(results)
```

## CLI Commands

| Command                        | Description                            |
| ------------------------------ | -------------------------------------- |
| `agentarmor init`              | Generate a config file                 |
| `agentarmor validate <config>` | Validate configuration                 |
| `agentarmor scan -t "text"`    | Scan text for threats                  |
| `agentarmor serve`             | Start proxy server                     |
| `agentarmor keygen`            | Generate encryption key                |
| `agentarmor-mcp`               | Start MCP server (stdio transport) *(v0.4.0)* |

## Custom Security Policies

```yaml
# policies/my_agent.yaml
version: "1.0"
name: "database_agent"
agent_type: "database"
risk_level: "high"

global_denied_actions:
  - "database.drop"
  - "database.truncate"

require_human_approval_for:
  - "database.delete"

rules:
  - name: "limit_transfer_amount"
    action_pattern: "transfer.*"
    conditions:
      - field: "params.amount"
        operator: ">"
        value: "1000"
    verdict: "escalate"
    priority: 100
```

## Architecture

```
                            MCP Agents (Claude Code, OpenClaw, Cursor, etc.)
                                       │
                                  stdio │ (agentarmor-mcp)
                                       ▼
Agent Runtime                   ┌─────────────────┐
(LangChain /                    │  MCP Server      │
 CrewAI /                       │  6 tools         │
 OpenAI SDK /  ─── Python ────► │  (v0.4.0)        │
 MCP)                           └────────┬─────────┘
         │                               │
         └───────────────┬───────────────┘
                         ▼
              ┌─────────────────────────────┐
              │      AgentArmor Pipeline     │
              │  ┌───────────────────────┐  │
              │  │  L8: Identity & IAM   │  │
              │  ├───────────────────────┤  │
              │  │  L1: Data Ingestion   │  │
              │  ├───────────────────────┤  │
              │  │  L2: Memory/Storage   │  │
              │  ├───────────────────────┤  │
              │  │  L3: Context Assembly │  │
              │  ├───────────────────────┤  │
              │  │  L4: Plan Validation  │  │
              │  ├───────────────────────┤  │
              │  │  L5: Action Execution │  │
              │  ├───────────────────────┤  │
              │  │  L7: Inter-Agent Sec  │  │
              │  └───────────────────────┘  │
              │  L6: Output Filter (post)   │
              │  Audit Logger (cross-cut)   │
              │  Policy Engine (cross-cut)  │
              └─────────────────────────────┘
                         │
                         ▼
                External Tools / APIs / LLMs
```

## OWASP ASI Coverage

| OWASP ASI Risk            | AgentArmor Layer(s)                          |
| ------------------------- | -------------------------------------------- |
| ASI01: Goal Hijacking     | L1 (injection), L3 (prompt hardening)        |
| ASI02: Tool Misuse        | L4 (planning), L5 (execution), Policy Engine |
| ASI03: Identity Abuse     | L8 (identity), L5 (JIT perms), OpenClaw Guard |
| ASI04: Supply Chain       | L1 (source verify), MCP Scanner              |
| ASI05: Code Execution     | L5 (sandbox), L4 (risk scoring)              |
| ASI06: Memory Poisoning   | L2 (integrity), L3 (canary tokens)           |
| ASI07: Inter-Agent        | L7 (mutual auth, trust scoring)              |
| ASI08: Cascading Failures | L4 (chain depth), L5 (rate limits)           |
| ASI09: Human Trust        | L6 (output filter), Audit Logger             |
| ASI10: Rogue Agents       | L8 (credential rotation), L7 (trust decay)   |

## Documentation

| Doc | Description |
|-----|-------------|
| [Quick Start](docs/quickstart.md) | Installation and first steps |
| [Claude Code Setup](docs/claude_code_setup.md) | MCP server setup for Claude Code, OpenClaw, Cursor |
| [Architecture](docs/architecture.md) | 8-layer pipeline design and data flow |
| [Integrations](docs/integrations.md) | MCP Server, OpenClaw, TLS/OAuth, LangChain, OpenAI |
| [Policy Language](docs/policy_language.md) | YAML policy reference and examples |
| [Threat Model](docs/threat_model.md) | OWASP ASI attack vectors and defenses |
| [Use Cases](docs/use_cases.md) | Financial, coding, RAG, multi-agent, MCP examples |
| [Publishing](docs/pypi_and_github.md) | PyPI & GitHub release guide |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0. Free for commercial and open-source use.
