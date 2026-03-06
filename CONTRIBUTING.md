# Contributing to AgentArmor

We welcome contributions! AgentArmor is an open research project — the goal is
to become the community standard for agentic AI security infrastructure.

## Development Setup

```bash
git clone https://github.com/agastyatodi/agentarmor.git
cd agentarmor
uv sync --all-extras
```

## Project Structure

- `src/agentarmor/layers/` — The 8 security layers. Each layer is a separate module.
- `src/agentarmor/policy/` — Policy engine and YAML policy format.
- `src/agentarmor/audit/` — Tamper-proof logging and OpenTelemetry tracing.
- `src/agentarmor/redteam/` — Automated adversarial test suite.
- `src/agentarmor/integrations/` — Framework integrations (LangChain, OpenAI, MCP).
- `tests/` — Pytest test suite. Run with `uv run pytest -v`.

## Adding a New Security Layer

1. Create `src/agentarmor/layers/myfeature/` with `__init__.py` and `myfeature.py`.
2. Subclass `SecurityLayer` from `agentarmor.core.base`.
3. Implement `async def process(self, event: AgentEvent) -> LayerResult`.
4. Add a `Config` class in `agentarmor.core.config`.
5. Wire it into `AgentArmor.__init__` in `pipeline.py`.
6. Add tests in `tests/unit/test_all.py`.
7. Add a red team test case in `redteam/suite.py`.

## Adding Red Team Tests

```python
from agentarmor.redteam.suite import TestCase, RedTeamSuite
from agentarmor.core.types import AgentEvent, SecurityVerdict

suite = RedTeamSuite(armor=armor)
suite.add_test(TestCase(
    id="ASI01-004",
    name="My new injection variant",
    category="ASI01_GoalHijacking",
    description="Tests XYZ injection variant",
    event=AgentEvent(
        agent_id="test",
        event_type="tool_call",
        action="scan.input",
        input_data="<your adversarial input>",
    ),
    expected_verdict=SecurityVerdict.DENY,
))
```

## Code Style

```bash
uv run ruff check .       # Lint
uv run ruff format .      # Format
uv run mypy src/          # Type check
```

## Opening Issues

- **Bug reports**: Include the full stack trace and your `AgentArmor` version.
- **New attack vectors**: We especially want contributions to the red team suite.
- **New integrations**: LlamaIndex, AutoGen, Google ADK, Haystack all needed.
- **ML-based detection**: A trained injection classifier to replace/augment the regex patterns in L1.
