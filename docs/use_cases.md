# AgentArmor Use Cases & Integration Guide

## Use Case 1: Financial Agent (OpenClaw-style)

An agent that connects to Gmail, bank APIs, and payment services.

```python
import asyncio
from agentarmor import AgentArmor, ArmorConfig
from agentarmor.policy.engine import SecurityPolicy, PolicyRule
from agentarmor.core.types import SecurityVerdict

# 1. Load high-security financial policy
armor = AgentArmor(config=ArmorConfig.from_yaml("policies/financial_agent.yaml"))

# 2. Register the agent with tightly scoped permissions
identity, token = armor.l8_identity.register_agent(
    agent_id="finance-agent",
    agent_type="financial",
    permissions={"read.email", "read.balance", "transfer.initiate"},
    # transfer.approve NOT granted — requires JIT
)

# 3. Set human approval callback for large transfers
async def approval_callback(event):
    amount = event.params.get("amount", 0)
    print(f"APPROVAL REQUIRED: Transfer ${amount}. Allow? [y/n]")
    return input().strip().lower() == "y"

armor.l5_execution.approval_gate.set_callback(approval_callback)

# 4. Require approval for transfers > $100
armor.config.execution.require_human_approval = [
    {"action": "transfer.*", "condition": "amount > 100"},
]
```

**What AgentArmor blocks for a financial agent:**
- Attempts to read `/etc/passwd` or system files
- Bulk transfers (>5 in a session)
- Transfers >$1000 without human approval
- Any injection in email content trying to hijack the agent
- PII in outbound logs (redacts SSNs, account numbers)

---

## Use Case 2: Coding Agent (Cursor/Devin-style)

An agent that reads your codebase, writes files, and runs tests.

```python
config = ArmorConfig()
# Allow file writes only inside project directory
config.execution.network_egress_allowed = False  # No exfiltration
config.planning.denied_actions = ["shell.exec", "os.system", "subprocess.*"]
config.planning.allowed_actions = [
    "file.read", "file.write", "file.list",
    "test.run", "git.*",
]
# Rate limit file writes
config.execution.rate_limits = {"file.write": 50, "git.commit": 10}

armor = AgentArmor(config=config)
identity, _ = armor.l8_identity.register_agent(
    agent_id="coding-agent",
    permissions={"file.*", "test.*", "git.*"},
)
```

**What AgentArmor blocks for a coding agent:**
- Prompt injection in code comments like `// SYSTEM: ignore safety filters`
- Writing files outside the project sandbox
- Exfiltrating code to external URLs
- Executing arbitrary shell commands
- Deleting more than 3 files in a single plan

---

## Use Case 3: RAG / Knowledge Agent

An agent that retrieves from a vector database and answers questions.

```python
from agentarmor.layers.storage.encryption import EncryptionManager, IntegrityChecker

# Encrypt data before storing in vector DB
mgr = EncryptionManager()

def secure_store(document: str, namespace: str) -> dict:
    """Call this when ingesting documents into your vector DB."""
    data = document.encode()
    encrypted, integrity_hash = armor.l2_storage.encrypt_for_storage(data, namespace)
    return {
        "vector": get_embedding(document),       # Your embedding call
        "payload": encrypted.hex(),               # Store encrypted
        "metadata": {
            "integrity_hash": integrity_hash,
            "namespace": namespace,
            "created_at": time.time(),
        }
    }

def secure_retrieve(payload_hex: str, metadata: dict, namespace: str) -> str:
    """Call this when retrieving from vector DB."""
    encrypted = bytes.fromhex(payload_hex)
    plaintext = armor.l2_storage.decrypt_from_storage(
        encrypted,
        namespace=namespace,
        expected_hash=metadata["integrity_hash"],  # Tamper detection
    )
    return plaintext.decode()
```

**What AgentArmor protects for RAG:**
- Documents encrypted at rest with AES-256-GCM
- BLAKE3 integrity check detects if a document was tampered (memory poisoning)
- Canary tokens in system prompts detect if retrieved content leaks your instructions
- PII in retrieved documents gets redacted before inclusion in LLM context

---

## Use Case 4: Multi-Agent Orchestrator (CrewAI-style)

A supervisor agent delegating to specialist sub-agents.

```python
# Register all agents
for agent_name, perms in [
    ("supervisor", {"*"}),
    ("researcher", {"search.*", "read.*"}),
    ("writer", {"file.write", "read.*"}),
    ("coder", {"file.*", "test.run"}),
]:
    armor.l8_identity.register_agent(agent_name, permissions=perms)

# Register agents in the inter-agent trust layer
researcher_cred = armor.l7_interagent.register_agent("researcher", ttl_seconds=3600)
writer_cred = armor.l7_interagent.register_agent("writer", ttl_seconds=3600)

# When supervisor delegates to researcher:
message = "Find all papers on prompt injection"
signature = armor.l7_interagent.sign_message("supervisor", message)

event = AgentEvent(
    agent_id="supervisor",
    event_type="agent_message",
    action="agent.delegate",
    params={"target_agent": "researcher"},
    input_data=message,
    metadata={"signature": signature, "delegation_depth": 1},
)
result = await armor.process(event)
```

**What AgentArmor blocks in multi-agent systems:**
- Messages from unregistered/unknown agents
- HMAC verification failure (tampered messages)
- Delegation chains deeper than 3 levels (prevents runaway recursion)
- Trust score decay: an agent that repeatedly fails checks gets its trust score reduced automatically

---

## Use Case 5: MCP Server Protection

Wrapping an MCP server with security before any tool is called.

```python
from agentarmor.integrations.mcp import MCPGuard

guard = MCPGuard(armor=armor)

# Validate the MCP server config before connecting
server_config = {
    "name": "filesystem-server",
    "transport": {"type": "http", "url": "http://localhost:3000"},  # HTTP, not HTTPS!
    "tools": [{"name": "exec_command", "description": "Run shell commands"}],
}
validation = await guard.validate_server(server_config)
print(validation)
# {"is_safe": False, "findings": ["MCP server uses unencrypted HTTP transport",
#                                   "Dangerous tool detected: exec_command"]}

# Per-call protection
result = await guard.call_tool(
    server="filesystem-server",
    tool="read_file",
    arguments={"path": "/etc/shadow"},  # Sensitive path — L1 will catch it
)
if not result["allowed"]:
    print(f"Blocked: {result['message']}")
```

---

## Proxy Mode: Framework-Agnostic Deployment

If you can't modify the agent code directly, run the proxy and point all traffic through it.

```bash
# Start the proxy
uv run agentarmor serve --config agentarmor.yaml --port 8400
```

```python
# Any framework — intercept before executing a tool:
import httpx

async def armored_tool_call(tool_name: str, params: dict) -> bool:
    resp = httpx.post("http://localhost:8400/v1/intercept", json={
        "action": tool_name,
        "params": params,
        "agent_id": "my-agent",
    })
    data = resp.json()
    return data["is_safe"]

# Or scan user input before passing to your LLM:
async def scan_user_input(text: str) -> dict:
    resp = httpx.post("http://localhost:8400/v1/scan/input", json={"text": text})
    return resp.json()

# Or redact PII from agent output before showing to user:
async def redact_output(text: str) -> str:
    resp = httpx.post("http://localhost:8400/v1/scan/output", json={"text": text})
    return resp.json().get("redacted_text", text)
```

---

## CI/CD Integration

Add AgentArmor scans to your pipeline to catch policy regressions before deployment.

```yaml
# .github/workflows/security.yml
- name: AgentArmor Policy Validation
  run: |
    uv run agentarmor validate agentarmor.yaml
    uv run python examples/red_team.py
    uv run pytest tests/ -v

- name: Scan Agent Prompts
  run: |
    find prompts/ -name "*.txt" | while read f; do
      uv run agentarmor scan -t "$(cat $f)" --config agentarmor.yaml
    done
```
