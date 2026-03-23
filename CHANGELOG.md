# Changelog

All notable changes to AgentArmor are documented in this file.

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
