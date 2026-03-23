---
description: Install local agentarmor from source (not pip) to avoid stale version conflicts
---

# Install AgentArmor from Local Source

Every time you start working on this project, the previously pip-installed version of `agentarmor-core` may conflict with the local development code. You **must** uninstall the old version and install from the local source in editable mode.

## Steps

// turbo-all

1. Uninstall any existing pip-installed version:
```bash
uv pip uninstall agentarmor-core
```

2. Install the local source code in editable mode:
```bash
uv pip install -e "c:\Users\agast\Downloads\agentarmor[dev]"
```

3. Verify the correct version is installed from the local path:
```bash
uv pip show agentarmor-core
```

> [!IMPORTANT]
> Never run `pip install agentarmor-core` or `uv pip install agentarmor-core` — that installs the **old** published version from PyPI, not the local development code.
