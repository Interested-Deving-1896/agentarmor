# Publishing AgentArmor — PyPI & GitHub

## Step 1: GitHub Repository Setup

```bash
# Inside the agentarmor/ directory
git init
git add .
git commit -m "feat: initial release of AgentArmor v0.1.0

8-layer defense-in-depth security framework for agentic AI applications.
Covers OWASP ASI Top 10 — ingestion, storage, context, planning, execution,
output, inter-agent, and identity security layers."

# Create the repo on GitHub (install gh CLI: https://cli.github.com)
gh repo create agastyatodi/agentarmor --public --push --source=.
```

Or manually:
1. Go to github.com → New Repository → Name: `agentarmor` → Public
2. `git remote add origin https://github.com/agastyatodi/agentarmor.git`
3. `git push -u origin main`

### Add GitHub Topics (increases discoverability):
Go to repo Settings → Topics → add:
`ai-security`, `llm-security`, `agent`, `guardrails`, `prompt-injection`,
`rag-security`, `mcp`, `owasp`, `langchain`, `openai`

---

## Step 2: GitHub Actions CI/CD

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
        with:
          python-version: ${{ matrix.python-version }}
      - run: uv sync --all-extras
      - run: uv run ruff check .
      - run: uv run mypy src/
      - run: uv run pytest -v --cov=agentarmor --cov-report=xml
      - uses: codecov/codecov-action@v4
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
```

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - "v*"   # Triggers on: git tag v0.1.0 && git push --tags

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write   # For trusted publishing (no token needed!)
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - run: uv build
      - uses: pypa/gh-action-pypi-publish@release/v1
```

---

## Step 3: PyPI Trusted Publishing (Recommended — no token needed)

PyPI Trusted Publishing uses OIDC — GitHub Actions proves it's publishing from
your repo without needing a stored API token.

1. Go to [pypi.org](https://pypi.org) → Log In → Your Account → Publishing
2. Add a new **pending publisher**:
   - PyPI Project Name: `agentarmor`
   - Owner: `agastyatodi`
   - Repository: `agentarmor`
   - Workflow: `publish.yml`
   - Environment: `pypi`
3. On GitHub: go to repo Settings → Environments → New environment → name it `pypi`

Then publish with:

```bash
git tag v0.1.0
git push --tags
# GitHub Actions automatically builds and publishes to PyPI
```

## Step 3 (Alternative): Manual PyPI Token

If you prefer a manual token:

1. Go to pypi.org → Account Settings → API Tokens → Add API Token
2. Name: `agentarmor-publish`, Scope: Entire Account (first upload)
3. Copy the `pypi-xxxxxxxxxxxx` token

```bash
# Build
uv build

# Publish
uv publish --token pypi-YOUR_TOKEN_HERE

# Or set as env var
export UV_PUBLISH_TOKEN=pypi-YOUR_TOKEN_HERE
uv publish
```

After first upload, regenerate the token scoped to only the `agentarmor` project.

---

## Step 4: Test on TestPyPI First

```bash
# Register at test.pypi.org separately
uv publish \
  --publish-url https://test.pypi.org/legacy/ \
  --token pypi-TEST_TOKEN

# Install from TestPyPI to verify
pip install --index-url https://test.pypi.org/simple/ agentarmor
python -c "import agentarmor; print(agentarmor.__version__)"
```

---

## Step 5: Release Checklist

Before every release:

```bash
# 1. Update version in pyproject.toml
# 2. Update CHANGELOG.md
# 3. Run full test suite
uv run pytest -v

# 4. Run red team
uv run python examples/red_team.py

# 5. Type check
uv run mypy src/

# 6. Lint
uv run ruff check .

# 7. Build and inspect
uv build
tar tzf dist/agentarmor-0.1.0.tar.gz | head -30

# 8. Tag and push
git tag v0.1.0 -m "Release v0.1.0: Initial public release"
git push --tags
```

---

## Docs Website (MkDocs)

For a proper docs site at `agastyatodi.github.io/agentarmor`:

```bash
uv add --dev mkdocs mkdocs-material

# Create mkdocs.yml at project root:
cat > mkdocs.yml << EOF
site_name: AgentArmor
site_description: 8-layer security framework for agentic AI
repo_url: https://github.com/agastyatodi/agentarmor
theme:
  name: material
  palette:
    primary: deep-purple
nav:
  - Home: index.md
  - Quickstart: quickstart.md
  - Architecture: architecture.md
  - Threat Model: threat_model.md
  - Policy Language: policy_language.md
  - Use Cases: use_cases.md
  - Contributing: ../CONTRIBUTING.md
EOF

# Symlink docs from project root
ln -s ../README.md docs/index.md

# Serve locally
uv run mkdocs serve

# Deploy to GitHub Pages
uv run mkdocs gh-deploy
```
