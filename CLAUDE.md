# AgentArmor

## What this is

AgentArmor is a Python security library that enforces 8-layer defense-in-depth for agentic AI applications, covering data at rest, in transit, and in use. It maps to the OWASP Top 10 for Agentic Applications (2026) and is the trust layer for AI agents.

## My role here

I am Agastya Todi, the maintainer of this repo.

## How to work in this repo

- Default model: Sonnet. Switch to Opus only for cross-cutting refactors or threat-model changes.
- Default effort: low. Bump to high only when explicitly told.
- Always read this file and the file you are editing. Do not read the whole tree.
- One PR per session. Branch name: claude/<issue-number>-<slug>.
- Never push to main. Never merge. Never bump versions.

## Stack

- Python 3.11+, packaged as `agentarmor-core` (hatchling build, source in src/agentarmor).
- Core deps: pydantic, cryptography, blake3, structlog, fastapi, httpx, tiktoken, pyyaml, jsonschema, ollama, argon2-cffi, keyring.
- Optional extras: proxy, pii (presidio), otel, mcp, oauth.
- Test runner: pytest with pytest-asyncio (asyncio_mode=auto, testpaths=["tests"]).
- Lint: ruff (select E,F,I,N,W,UP,B,SIM, line-length 120). Type check: mypy strict.
- CLI entry points: `agentarmor`, `agentarmor-mcp`.

## Threat model in one paragraph

AgentArmor defends against prompt injection, goal hijacking, tool misuse, memory poisoning, credential and PII exfiltration, multi-step attack chains, and rogue agent coordination (OWASP ASI01 through ASI10). Treat every LLM response, tool output, and stored document as attacker controlled. Never exec or eval dynamic strings. All persisted state is AES-256-GCM encrypted and HMAC signed.

## Layers (so Claude knows the architecture)

- L1 Ingestion: input scanning, prompt injection detection, source verification.
- L2 Storage: AES-256-GCM encryption at rest, HMAC integrity, tamper detection.
- L3 Context: GoalLock anchoring, multi-canary injection, template injection stripping.
- L4 Planning: action chain tracking, semantic risk scoring, multi-step attack detection.
- L5 Execution: DNS rebinding protection, rate limiting, circuit breakers, resource budgets.
- L6 Output: credential redaction, PII scanning, harmful content blocking, exfiltration detection.
- L7 Inter-Agent: mutual HMAC auth, trust scoring with time decay, delegation depth control.
- L8 Identity: agent identity, JIT permissions, credential rotation.

## What NOT to touch without asking

- SECURITY.md, LICENSE, /docs/public/\*
- Release workflows, version bumps (pyproject.toml version, CHANGELOG.md).
- Anything in a directory whose name starts with vendor/.

## Tests and CI

- Run tests: `uv run pytest`.
- Lint: `uv run ruff check .`.
- Type check: `uv run mypy src/`.
- Only in-repo workflow is .github/workflows/desktop-release.yml, which builds the Studio installer on `desktop-v*` tags (matrix: windows-latest, ubuntu-latest, macos-latest aarch64).

## When you finish

Post a 5-bullet summary in the PR description: what changed, why, files touched, tests added, follow-ups. Stop. Do not start another task.
