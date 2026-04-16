# Hardened Security Layers — v0.6.0

AgentArmor v0.6.0 includes production-grade hardening across all 8 security layers, validated by **145+ adversarial test cases**. This document describes what each layer protects and how to use it.

---

## L1 — Data Ingestion Scanner

**What it does:** Scans all inbound data for injection attempts, jailbreaks, and malicious payloads before they enter the agent pipeline.

**Capabilities:**
- Multiple detection categories: prompt injection, jailbreak attempts, extraction attacks, exfiltration payloads, encoded payloads, Unicode steganography
- Source provenance tracking
- Configurable size limits

**Usage:**
```python
from agentarmor import AgentArmor

armor = AgentArmor()
result = await armor.process(AgentEvent(
    agent_id="my-agent",
    event_type="scan",
    action="ingestion.scan",
    input_data=user_input,
))

if result.is_blocked:
    print(f"Blocked: {result.blocked_by}")
```

---

## L2 — Encrypted Storage

**What it does:** Protects data at rest with authenticated encryption and tamper detection.

**Capabilities:**
- AES-256-GCM authenticated encryption for all stored data
- BLAKE3 hash chaining for audit log integrity
- HMAC-based MAC signatures on events and messages
- Automatic `L2_TAMPER_ALERT` when MAC verification fails
- Namespace-based access isolation

---

## L3 — Context Assembly Security

**What it does:** Prevents goal hijacking and system prompt leakage through structural enforcement.

**Capabilities:**
- **GoalLock** — Anchors agent purpose at conversation start; detects goal drift
- **CanaryVault** — Session-scoped canary tokens detect prompt leakage in outputs
- **Tiered Context** — Structural separation of instructions vs. user data
- **Template Injection Stripping** — Removes injection patterns pre-LLM
- **Datamarking** — Tags user content to prevent privilege escalation

**Usage:**
```python
from agentarmor.layers.context.assembler import L3ContextLayer

l3 = L3ContextLayer(
    agent_id="my-agent",
    agent_config={"system_prompt": "You are helpful.", "tools": ["web_search"]},
)

# Build hardened system prompt
hardened = l3.build_secure_system_prompt(
    base_system_prompt="You are helpful.",
    conversation_id="session-1",
)

# Check output for canary leaks and goal drift
safe_response, events = await l3.check_output(
    conversation_id="session-1",
    response=llm_response,
    tool_calls=[],
    turn_number=1,
    user_message=user_input,
)
```

---

## L4 — Planning & Reasoning Validation

**What it does:** Detects multi-step attack patterns and evaluates action risk before execution.

**Capabilities:**
- **ActionChainTracker** — Detects reconnaissance → escalation → exfiltration chains
- **Semantic Risk Scoring** — Evaluates intent and target sensitivity
- Hard-deny for high-risk actions (EXECUTE, ADMIN)
- Bulk operation detection
- Chain depth limits

**Usage:**
```python
from agentarmor.layers.planning.l4_planning import L4PlanningLayer

l4 = L4PlanningLayer(agent_id="my-agent")

verdict, event = await l4.evaluate_tool_call(
    tool_name="file_read",
    tool_args={"path": "/etc/shadow"},
    session_id="session-1",
)

if verdict == "block":
    print("Tool call blocked by L4")
```

---

## L5 — Execution Control (5-Domain Enforcement)

**What it does:** Controls how and whether actions execute through five enforcement domains.

**Domains:**
| Domain | What It Does |
|--------|-------------|
| E1: Network Policy | DNS rebinding protection, protocol enforcement, domain allowlist/blocklist |
| E2: Rate Limiting | Token bucket per tool with circuit breaker on failure streaks |
| E3: Resource Budget | Execution timeout + input/output size limits |
| E4: Output Sanitizer | UTF-8 normalization, binary stripping, truncation |
| E5: Side-Effect Auditor | Immutable SHA-256 execution records |

**Usage:**
```python
from agentarmor.layers.execution.l5_execution import L5ExecutionLayer, NetworkPolicy

l5 = L5ExecutionLayer(
    agent_id="my-agent",
    network_policy=NetworkPolicy(
        allow_http=False,
        domain_allowlist=["api.github.com"],
        domain_blocklist=["metadata.google.internal"],
        dns_rebinding_protection=True,
    ),
)

result, event = await l5.execute(
    tool_name="api_call",
    tool_args={"url": "https://api.github.com/repos"},
    tool_func=my_api_function,
    session_id="session-1",
    outbound_url="https://api.github.com/repos",
)
```

---

## L6 — Output Security (5-Scanner Pipeline)

**What it does:** Scans every output for credentials, PII, harmful content, and exfiltration patterns.

**Scanners:**
| Scanner | What It Catches |
|---------|----------------|
| O1: Credential Scanner | AWS keys, JWTs, DB strings, API tokens (13+ patterns) |
| O2: PII Scanner | Emails, phone numbers, SSNs, names (confidence-gated) |
| O3: Harmful Content | Jailbreak markers, system prompt leaks, unsafe patterns |
| O4: Semantic Exfiltration | Bulk PII extraction across responses |
| O5: Schema Validation | Output structure enforcement |

**Usage:**
```python
from agentarmor.layers.output.filter import L6OutputLayer

l6 = L6OutputLayer(
    agent_id="my-agent",
    enable_pii_scan=True,
    enable_harmful_scan=True,
)

safe_text, result = l6.process(llm_response, session_id="session-1")
print(f"Findings: {result['findings_count']}, Verdict: {result['verdict']}")
```

---

## L7 — Inter-Agent Communication Security *(Hardened in v0.6.0)*

**What it does:** Secures message passing in multi-agent systems through 5 enforcement components.

**Components:**
| Component | What It Does |
|-----------|-------------|
| T1: Replay Prevention | Nonce registry (10K cap) + timestamp freshness (300s skew) |
| T2: Delegation Certificates | HMAC-signed certs with scope restriction + depth limits (max=3) |
| T3: Directed-Pair Trust | Per-pair trust with 2%/hr decay, event-specific deltas, trust-gated tiers |
| T4: Scope Binding | Global scope + forbidden actions with wildcard matching |
| T5: Behavioral Baseline | Rolling window (20 actions) anomaly detection — BLOCK at >0.9 |

**Trust-Gated Tiers:**
| Score Range | Policy |
|-------------|--------|
| 0.7 – 1.0 | ALLOW |
| 0.4 – 0.7 | ALLOW + enhanced logging |
| 0.2 – 0.4 | Require re-verification of delegation certificate |
| 0.0 – 0.2 | BLOCK all messages |

**Usage:**
```python
from agentarmor.layers.interagent.l7_interagent import (
    L7InterAgentLayer,
    create_delegation,
)

# Receiver side
l7 = L7InterAgentLayer(agent_id="agent-b")
secret = l7.register_peer(
    peer_id="agent-a",
    scope=["web_search", "file_read"],
    forbidden=["admin.*", "database.drop"],
)

# Sender side — create a signed message
from agentarmor.layers.interagent.l7_interagent import create_signed_payload
msg = create_signed_payload("agent-a", "agent-b", "web_search", {"q": "hello"}, secret)

# Receiver verifies
result, event = l7.verify_incoming(msg)
print(f"Verdict: {result.value}, Trust: {event.details.get('trust_score')}")

# Delegation: agent-a delegates to agent-c
cert = create_delegation("agent-a", "agent-c", ["web_search"], secret, max_depth=3)
result, event = l7.verify_incoming(msg, delegation_cert=cert)
```

---

## L8 — Identity & Access Management

**What it does:** Enforces agent identity, permissions, and credential lifecycle.

**Capabilities:**
- Agent registration with UUID-based identity
- Token-based credential issuance with configurable TTL
- Glob-pattern permission matching (`read.*`, `database.*`)
- JIT (Just-In-Time) permission grants with automatic expiry
- Short-lived credentials (default 3600s) to limit blast radius of theft

---

## Cross-Cutting Concerns

### Policy Engine
Runs **before** the layer pipeline on every event. Provides declarative, YAML-based policy rules with glob-pattern matching, conditional logic, and priority-ordered evaluation.

### Audit Logger
Tamper-proof logging of every security event with BLAKE3 hash chaining and OpenTelemetry span export.

---

## Validation Summary

| Layer | Test Cases | Status |
|-------|-----------|--------|
| L1 Ingestion | Included in L3/L4 suites | ✅ Pass |
| L2 Storage | MAC integrity checks | ✅ Pass |
| L3 Context | 48 adversarial cases | ✅ Pass |
| L4 Planning | 40 adversarial cases | ✅ Pass |
| L5 Execution | 39 adversarial cases | ✅ Pass |
| L6 Output | 12 adversarial cases | ✅ Pass |
| L7 Inter-Agent | 18 adversarial cases | ✅ Pass |
| L8 Identity | Permission matching | ✅ Pass |
