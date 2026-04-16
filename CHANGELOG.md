# Changelog

All notable changes to AgentArmor are documented in this file.

## [0.6.0] — 2026-04-16

### 🚀 L7 Inter-Agent Layer: Full Hardening

Five components replace the basic HMAC-only implementation with production-grade inter-agent security. **18 test cases** validate the hardened layer.

#### T1: Replay Prevention
- Mandatory `timestamp` (unix epoch) and `nonce` (32 hex chars) on every inter-agent message
- `NonceRegistry` with TTL=600s, cap at 10,000 entries, automatic expired sweep
- `MAX_CLOCK_SKEW` = 300 seconds — messages older than 5 minutes are rejected
- Returns specific `VerifyResult` enum: `ALLOW`, `REPLAY_EXPIRED`, `REPLAY_DETECTED`, `TAMPERED`

#### T2: Delegation Chain Authorization
- `DelegationCertificate` dataclass with HMAC-signed fields (scope, depth, TTL, task description)
- `max_depth` default = 3 — prevents infinite recursive delegation (SentinelAgent attack vector)
- Scope restriction: delegated agents can only call actions listed in `authorized_scope`
- Certificate TTL capped at 1 hour

#### T3: Directed-Pair Trust with Hourly Decay
- Trust is per directed pair (A→B), not per agent globally
- Hourly decay: `effective = stored × (0.98 ^ hours_inactive)`
- Event-specific deltas: `CERT_TAMPERED` = -0.40, `REPLAY_DETECTED` = -0.30, `MESSAGE_VERIFIED` = +0.02
- Trust-gated tiers: ≥0.7 ALLOW, 0.4–0.7 enhanced logging, 0.2–0.4 re-verification, <0.2 BLOCK

#### T4: Scope Binding
- `ScopeManifest` per agent: `global_scope` (allowed actions) + `forbidden_always` (hard deny)
- Wildcard matching support (`web_*` matches `web_search`)
- Prevents privilege escalation through delegation — you cannot delegate permissions you don't own

#### T5: Behavioral Anomaly Detection
- `BehavioralBaseline` with rolling window of 20 actions per peer
- Actions categorized: read, write, network, system
- Anomaly score 0.0 (normal) to 1.0 (completely anomalous)
- Score > 0.7: emit HIGH warning event; Score > 0.9: BLOCK + CRITICAL + trust penalty

### Files
- **New:** `src/agentarmor/layers/interagent/l7_interagent.py`
- **New:** `desktop/sidecar/test_l7_validation.py` (18 checks)

## [0.5.0] — 2026-04-16

### 🚀 Major: Production-Grade Layer Hardening

This release upgrades L2–L6 from basic implementations to adversarially-tested enforcement engines.  
**127+ test cases** validate the hardened layers across prompt injection, goal hijacking, multi-step attacks, credential leaks, and semantic exfiltration.

#### L2: Encrypted Storage with Tamper Detection
- All data stored in Studio's SQLite database is now AES-256-GCM encrypted
- HMAC-based MAC signatures on all events and messages for tamper detection
- Automatic `L2_TAMPER_ALERT` flagging when MAC verification fails

#### L3: Hardened Context Assembly
- **GoalLock** — Anchors agent purpose at conversation start; detects goal drift across turns
- **CanaryVault** — Injects multiple unique canary tokens per session; detects system prompt leakage
- **Tiered Context Assembly** — Structural separation of system instructions vs. user data
- **Template Injection Stripping** — Removes structural template injection before LLM processing
- **Datamarking** — Tags user-provided data to prevent privilege escalation
- Validated against 48 adversarial test cases

#### L4: Hardened Planning & Reasoning
- **ActionChainTracker** — Detects multi-step attack patterns (recon → escalation → exfiltration)
- **Semantic Risk Scoring** — Evaluates action intent and target sensitivity, not just verbs
- **Param-Aware Scoring** — `read.file /etc/shadow` scores higher than `delete.file /tmp/cache`
- **Bulk Operation Detection** — Flags coordinated destructive actions
- Validated against 40 adversarial test cases

#### L5: Hardened Execution Control (5-Domain Enforcement)
- **E1: Network Policy** — DNS resolution + private IP check + protocol enforcement + domain allowlist/blocklist
- **E2: Rate Limiting** — Token bucket per tool with circuit breaker on failure streaks
- **E3: Resource Budget** — Execution timeout + input/output size limits
- **E4: Output Sanitizer** — UTF-8 normalization + binary stripping + truncation
- **E5: Side-Effect Auditor** — Immutable SHA-256-hashed execution records
- DNS rebinding protection (blocks resolution to private IPs)
- Validated against 39 adversarial test cases

#### L6: Hardened Output Security (5-Scanner Pipeline)
- **O1: Credential Scanner** — 13+ regex patterns (AWS, JWT, DB strings, GitHub/Slack/Stripe tokens) with zero-false-positive design
- **O2: PII Scanner** — Confidence-gated Presidio integration with per-entity thresholds
- **O3: Harmful Content Detector** — Jailbreak markers, system prompt leakage, CBRN patterns
- **O4: Semantic Exfiltration Detector** — Cross-response tracking detects bulk PII/credential extraction
- **O5: Schema Validation** — Structure enforcement for agent outputs
- Full streaming support with buffer-and-flush strategy
- Validated against 12 adversarial test cases

### Other Changes
- Version bumped to 0.5.0
- Updated documentation across all docs

## [0.4.1] — 2026-03-23

### Bug Fixes

#### L4: Param-Aware Risk Scoring
- **Fixed:** `_categorize_action` scored actions purely by verb, ignoring target parameters. `read.file /etc/shadow` scored 1 while `delete.file /tmp/cache.json` scored 7 — backwards from a security perspective.
- **Change:** Risk scoring now uses `composite_score = verb_score × target_multiplier` (capped at 10). Target sensitivity is determined by fnmatch glob patterns against the action's path/resource parameters.
- **New files:** `layers/planning/target_sensitivity.py`, `tests/unit/test_target_sensitivity.py`
- **Modified:** `layers/planning/validator.py`, `core/types.py` (added `RiskScore` model)

#### L7: Time-Based Trust Decay
- **Fixed:** `TrustScorer` accepted a `decay_rate` parameter but never applied it. Dormant agents retained their trust score indefinitely.
- **Change:** `get_score()` now computes `effective_trust = stored_trust × (decay_rate ^ days_since_last_interaction)` on every call. Decayed values are not persisted — only actual interactions update the stored trust.
- **New files:** `tests/unit/test_trust_decay.py`
- **Modified:** `layers/interagent/trust.py` (added `TrustRecord` model, `get_trust_debug_info()`, `_ScoresProxy` for backward compat)

## [0.4.0] — 2026-03-14

- MCP Server Plugin — AgentArmor as a native MCP server
- 6 MCP Tools for zero-code security
- `agentarmor-mcp` CLI entry point

## [0.3.0] — 2026-03-14

- TLS Certificate Validation for MCP servers
- OAuth 2.1 Compliance Checker with PKCE S256
- `MCPGuard.full_security_scan()` combined scan

## [0.2.0] — 2026-03-14

- OpenClaw Identity Guard (AES-256-GCM + BLAKE3)
- MCP Server Scanner (dangerous tools, rug-pulls, transport security)
