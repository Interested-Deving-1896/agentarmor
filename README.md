# 🛡️ AgentArmor

**Comprehensive open-source security framework for agentic AI applications.**

AgentArmor provides 8-layer defense-in-depth security for AI agents, covering every point in the data flow where data is at rest, in transit, or in use. Built to address the [OWASP Top 10 for Agentic Applications (2026)](https://owasp.org/www-project-top-10-for-agentic-security-and-integrity/).

---

## Why AgentArmor?

Every existing security tool is a **point solution** — output validators, prompt injection scanners, or policy engines in isolation. AgentArmor is the **first unified framework** that secures the entire agentic architecture end-to-end.

## The 8 Security Layers

| Layer | Name | What It Protects |
|-------|------|-----------------|
| L1 | **Ingestion** | Input scanning, prompt injection detection, source verification |
| L2 | **Storage** | Encryption at rest (AES-256-GCM), data classification, integrity (BLAKE3) |
| L3 | **Context** | Instruction-data separation, canary tokens, prompt hardening |
| L4 | **Planning** | Action plan validation, risk scoring, chain depth limits |
| L5 | **Execution** | Rate limiting, network egress control, human approval gates |
| L6 | **Output** | PII redaction (Presidio), DLP, sensitivity filtering |
| L7 | **Inter-Agent** | Mutual auth (HMAC), trust scoring, delegation depth control |
| L8 | **Identity** | Agent identity, JIT permissions, credential rotation |

## Quick Start

### Install

```bash
# Using uv (recommended)
uv add agentarmor

# With all optional features
uv add "agentarmor[all]"

# For development
git clone https://github.com/agastyatodi/agentarmor.git
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
        input_data="Read the user notes file",
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

### Framework Integrations

```python
# LangChain
from agentarmor.integrations.langchain import AgentArmorCallback
callback = AgentArmorCallback(armor=armor)
agent.invoke({"input": "..."}, config={"callbacks": [callback]})

# OpenAI
from agentarmor.integrations.openai import secure_openai_client
client = secure_openai_client(OpenAI(), armor=armor)

# MCP
from agentarmor.integrations.mcp import MCPGuard
guard = MCPGuard(armor=armor)
result = await guard.call_tool("my-server", "read_file", {"path": "/data"})
```

### Red Team Testing

```python
from agentarmor.redteam import RedTeamSuite

suite = RedTeamSuite(armor=armor)
results = await suite.run_all()
suite.print_report(results)
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `agentarmor init` | Generate a config file |
| `agentarmor validate <config>` | Validate configuration |
| `agentarmor scan -t "text"` | Scan text for threats |
| `agentarmor serve` | Start proxy server |
| `agentarmor keygen` | Generate encryption key |

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
Agent Runtime (LangChain / CrewAI / OpenAI SDK / MCP)
         │
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

| OWASP ASI Risk | AgentArmor Layer(s) |
|---------------|-------------------|
| ASI01: Goal Hijacking | L1 (injection), L3 (prompt hardening) |
| ASI02: Tool Misuse | L4 (planning), L5 (execution), Policy Engine |
| ASI03: Identity Abuse | L8 (identity), L5 (JIT perms) |
| ASI04: Supply Chain | L1 (source verify), MCP Guard |
| ASI05: Code Execution | L5 (sandbox), L4 (risk scoring) |
| ASI06: Memory Poisoning | L2 (integrity), L3 (canary tokens) |
| ASI07: Inter-Agent | L7 (mutual auth, trust scoring) |
| ASI08: Cascading Failures | L4 (chain depth), L5 (rate limits) |
| ASI09: Human Trust | L6 (output filter), Audit Logger |
| ASI10: Rogue Agents | L8 (credential rotation), L7 (trust decay) |

## License

Apache 2.0. Free for commercial and open-source use.
