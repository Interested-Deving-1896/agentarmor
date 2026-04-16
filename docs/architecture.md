# AgentArmor Architecture

## Overview

AgentArmor is structured as an **8-layer pipeline** that intercepts every event in
an agent's lifecycle. Each layer is independently configurable and composable.

```
                         ┌─────────────────────────────────────┐
                         │          AgentArmor Pipeline         │
                         │                                      │
Agent Runtime  ──────►  │  L8 Identity & Access Management     │
(LangChain /             │       ↓                              │
 CrewAI /                │  L1 Data Ingestion Scanner           │
 OpenAI SDK /            │       ↓                              │
 MCP /                   │  L2 Memory & Storage Security        │
 Raw Ollama)             │       ↓                              │
                         │  L3 Context Assembly Security        │
                         │       ↓                              │
                         │  L4 Reasoning & Plan Validation      │
                         │       ↓                              │
                         │  L5 Action Execution Control         │
                         │       ↓                              │
                         │  L7 Inter-Agent Communication Auth   │
                         │                                      │
                         │  ┄┄┄┄┄┄┄ cross-cutting ┄┄┄┄┄┄┄┄    │
                         │  Policy Engine (pre-pipeline)        │
                         │  Audit Logger (every event)          │
                         │  L6 Output Filter (post-pipeline)    │
                         └─────────────────────────────────────┘
                                         │
                                         ▼
                              External Tools / APIs / LLMs
```

## Layer Details

### L8 — Identity & Access Management
**File:** `src/agentarmor/layers/identity/manager.py`

The first layer in the pipeline. Every event must pass identity verification before
any other check runs. This ensures no anonymous agent can trigger any security layer.

- Agent registration with UUID-based identity
- Token-based credential issuance with configurable TTL
- Glob-pattern permission matching (`read.*`, `database.*`)
- JIT (Just-In-Time) permission grants with automatic expiry
- Short-lived credentials (default 3600s) to limit blast radius of theft

### L1 — Data Ingestion Scanner
**File:** `src/agentarmor/layers/ingestion/scanner.py`

Scans all inbound data — user messages, retrieved documents, tool responses —
for injection attempts, malicious payloads, and oversized inputs.

- 20+ regex patterns covering: prompt injection, jailbreaks, extraction attempts,
  exfiltration payloads, encoded payloads, Unicode steganography
- Source provenance tracking
- Configurable size limits

### L2 — Memory & Storage Security *(Hardened in v0.5.0)*
**File:** `src/agentarmor/layers/storage/encryption.py`

Protects data at rest in vector databases, knowledge graphs, and caches.

- AES-256-GCM authenticated encryption (provides both confidentiality + integrity)
- BLAKE3 hash chaining for tamper detection
- HMAC-based MAC signatures on all stored events and messages
- Automatic `L2_TAMPER_ALERT` flagging when MAC verification fails
- Namespace-based access isolation
- Detects memory poisoning: if a retrieved document's hash doesn't match, CRITICAL deny

### L3 — Context Assembly Security *(Hardened in v0.5.0)*
**File:** `src/agentarmor/layers/context/assembler.py`

Protects the LLM's context window construction with production-grade enforcement.

- **GoalLock Anchoring**: Anchors the agent's core purpose at conversation start; detects semantic goal drift across turns by comparing response alignment with the original directive
- **CanaryVault**: Injects multiple unique session-scoped canary tokens into system prompts; if any appear in outputs, the system prompt was leaked and the response is blocked
- **Tiered Context Assembly**: Structurally separates system instructions from user data with enforced boundaries, preventing privilege escalation through data injection
- **Template Injection Stripping**: Detects and removes structural template injection patterns before they reach the LLM
- **Datamarking**: Tags user-provided content with markers that prevent it from being interpreted as system-level instructions
- Context token count enforcement
- Validated against 48 adversarial test cases

### L4 — Reasoning & Plan Validation *(Hardened in v0.5.0)*
**File:** `src/agentarmor/layers/planning/validator.py`, `layers/planning/l4_planning.py`

Intercepts the agent's planned actions before they execute.

- **ActionChainTracker**: Detects multi-step attack patterns across a session — reconnaissance followed by privilege escalation followed by data exfiltration triggers an automatic block
- **Semantic Risk Scoring**: Evaluates action intent and target sensitivity, not just the verb. `read.file /etc/shadow` is correctly scored as higher risk than `delete.file /tmp/cache`
- Hard-deny for EXECUTE (8+) and ADMIN (10) actions
- ESCALATE (human approval) for DELETE (7) actions
- Bulk operation detection (coordinated destructive actions)
- Configurable chain depth limits (prevent infinite loops)
- Explicit allow/deny action lists with glob pattern support
- Validated against 40 adversarial test cases

### L5 — Action Execution Control *(Hardened in v0.5.0)*
**File:** `src/agentarmor/layers/execution/l5_execution.py`

Controls how and whether agent actions execute through five enforcement domains.

- **E1: Network Policy** — DNS resolution with private IP blocking (SSRF/DNS rebinding defense), protocol enforcement (blocks `file://`, `gopher://`, etc.), domain allowlist/blocklist with wildcard support
- **E2: Rate Limiting** — Token bucket per tool action with automatic circuit breaker on failure streaks
- **E3: Resource Budget** — Per-execution timeout enforcement + input/output size limits
- **E4: Output Sanitizer** — UTF-8 normalization, binary content stripping, safe truncation
- **E5: Side-Effect Auditor** — Immutable SHA-256-hashed execution records for forensic analysis
- Human approval gates with async callback for high-risk operations
- Validated against 39 adversarial test cases

### L6 — Output Filter *(Hardened in v0.5.0)*
**File:** `src/agentarmor/layers/output/filter.py`

Post-processes agent output before it reaches users or downstream systems through a 5-scanner pipeline.

- **O1: Credential Scanner** — Detects and redacts credentials (cloud provider keys, JWTs, database connection strings, API tokens) with zero-false-positive design. Always active.
- **O2: PII Scanner** — Confidence-gated Presidio integration with per-entity threshold tuning to minimize false positives while catching real PII
- **O3: Harmful Content Detector** — Detects jailbreak mode markers, system prompt leakage, and unsafe content patterns (defense-in-depth with L3 canary detection)
- **O4: Semantic Exfiltration Detector** — Session-scoped tracking that flags patterns of bulk PII or credential extraction across multiple responses
- **O5: Schema Validation** — Structure enforcement for agent outputs
- Full streaming support with buffer-and-flush strategy for SSE responses
- Validated against 12 adversarial test cases

### L7 — Inter-Agent Communication Security
**File:** `src/agentarmor/layers/interagent/trust.py`

Secures message passing in multi-agent systems.

- Agent registry — only registered agents can communicate
- HMAC-SHA256 message signing and verification
- Trust scoring: starts at 0.5, rises with successful interactions, decays on failures
- Min trust score threshold (default: 0.7)
- Max delegation depth to prevent infinite agent chains
- Timestamp-bound signatures (5-minute window) prevent replay attacks

## Cross-Cutting Concerns

### Policy Engine
**File:** `src/agentarmor/policy/engine.py`

Runs **before** the layer pipeline on every event. Provides declarative, YAML-based
policy rules that complement the layer checks. Rules support:
- Glob-pattern action matching
- Conditional logic with field operators
- Priority-ordered evaluation
- Verdicts: allow, deny, escalate, audit

### Audit Logger
**File:** `src/agentarmor/audit/logger.py`

Tamper-proof logging of every security event.

- BLAKE3 hash chaining: each log entry includes the hash of the previous entry,
  so any tampering is detectable
- Structured JSON logging via `structlog`
- OpenTelemetry span export for distributed tracing
- Captures: event metadata, layer results, verdicts, processing time, threat level

## Data Flow

```
1. Agent calls armor.intercept(action, params, agent_id, input_data)
2. Policy Engine: check declarative rules → fast-path allow/deny
3. L8: verify agent identity and token
4. L1: scan input_data for threats
5. L2: verify storage integrity (if memory event)
6. L3: validate context structure and canary tokens
7. L4: score action risk, validate plan
8. L5: check rate limits, network policy, approval gates
9. L7: verify inter-agent auth (if agent_message event)
10. Audit: log PipelineResult with full layer trace
11. Return PipelineResult to caller
    ↓
12. Caller executes actual tool (if is_safe)
    ↓
13. armor.scan_output(output_event) → L6 PII filter
14. Return redacted output to user/LLM
```

## Extension Points

- **New security layer**: subclass `SecurityLayer`, implement `process()`, wire into `pipeline.py`
- **New policy rule type**: extend `PolicyRule` in `policy/engine.py`
- **New integration**: add to `integrations/` — see `integrations/langchain/` as reference
- **New red team test**: add `TestCase` to `redteam/suite.py`
- **Custom PII entities**: register with `presidio_analyzer` in `layers/output/filter.py`

### Built-in Integrations (v0.4.0)

| Integration | Module | Purpose |
|-------------|--------|---------|
| **MCP Server** *(v0.4.0)* | `integrations/mcp_server/` | Native MCP server — 6 security tools callable by Claude Code, OpenClaw, Cursor, etc. |
| **TLS Validator** *(v0.3.0)* | `integrations/mcp/tls_validator.py` | Validate TLS certificates, cipher suites, expiry |
| **OAuth 2.1 Verifier** *(v0.3.0)* | `integrations/mcp/oauth_verifier.py` | Verify OAuth 2.1 compliance, PKCE S256, PRM/ASM |
| **OpenClaw Guard** | `integrations/openclaw/` | Encrypt agent identity files (SOUL.md, MEMORY.md, etc.) |
| **MCP Scanner** | `integrations/mcp/guard.py` | Scan MCP servers for dangerous tools and rug-pulls |
| **LangChain** | `integrations/langchain/` | Callback-based tool call interception |
| **OpenAI** | `integrations/openai/` | Secure client wrapper for OpenAI API |

### MCP Server Data Flow (v0.4.0)

```
MCP Agent (Claude Code, OpenClaw, Cursor, etc.)
    │
    │ stdio (JSON-RPC over stdin/stdout)
    │
    ▼
┌─────────────────────────────────────┐
│  AgentArmor MCP Server              │
│  (agentarmor-mcp)                   │
│                                     │
│  armor_scan_input ──► L1 Ingestion  │
│  armor_intercept ──► Full Pipeline  │
│  armor_scan_output ──► L6 Output    │
│  armor_scan_mcp_server ──► MCPGuard │
│  armor_register_agent ──► L8 Ident  │
│  armor_get_status ──► Health Check  │
└─────────────────────────────────────┘
    │
    ▼
  AgentArmor Pipeline (8 layers)
    │
    ▼
  JSON response back to agent
```

The MCP server provides a **zero-code** path to AgentArmor's security pipeline.
Agents call tools via the standard MCP protocol and receive JSON responses with
verdicts, threat levels, and actionable messages.

See [integrations.md](integrations.md) for full usage documentation.

