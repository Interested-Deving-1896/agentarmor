"""Tests for AgentArmor MCP Server — no live network, no MCP client needed."""

import pytest


def test_mcp_available_or_skip():
    """Skip all MCP server tests if mcp package not installed."""
    import importlib.util
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("mcp package not installed — run: uv add 'mcp>=1.0'")


def test_server_creates_without_error():
    try:
        from agentarmor.integrations.mcp_server.server import create_server
        assert create_server() is not None
    except (ImportError, NameError):
        pytest.skip("mcp not installed")


def test_run_function_exists():
    from agentarmor.integrations.mcp_server.server import run
    assert callable(run)


@pytest.mark.asyncio
async def test_get_status_returns_all_layers():
    try:
        from agentarmor.integrations.mcp_server.server import _get_armor, create_server
        create_server()
        # Call tool handler directly
        # We test the logic by instantiating armor and checking layers
        armor = _get_armor()
        assert armor.l1_ingestion is not None
        assert armor.l8_identity is not None
    except (ImportError, NameError):
        pytest.skip("mcp not installed")


def test_pkce_utility_accessible():
    """OAuthVerifier.generate_pkce_pair should work from MCP context."""
    from agentarmor.integrations.mcp.oauth_verifier import OAuthVerifier
    verifier, challenge = OAuthVerifier.generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) >= 43


def test_mcp_server_entry_point_in_pyproject():
    """Verify agentarmor-mcp is declared as a script entry point."""
    import tomllib
    from pathlib import Path
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        pytest.skip("pyproject.toml not found")
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    scripts = data.get("project", {}).get("scripts", {})
    assert "agentarmor-mcp" in scripts, (
        "agentarmor-mcp not in [project.scripts] — "
        "add: agentarmor-mcp = 'agentarmor.integrations.mcp_server.server:run'"
    )
