import pytest
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path


def test_openclaw_scan_no_directory():
    from agentarmor.integrations.openclaw import OpenClawGuard
    guard = OpenClawGuard(identity_dir="/nonexistent/path/xyz")
    report = guard.scan()
    assert report["exists"] is False
    assert report["risk_level"] == "unknown"


def test_openclaw_encrypt_decrypt_roundtrip():
    from agentarmor.integrations.openclaw import OpenClawGuard
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_dir = Path(tmpdir)
        soul_file = identity_dir / "SOUL.md"
        soul_file.write_text("# Agent Soul\nI am a helpful assistant.")

        guard = OpenClawGuard(identity_dir=str(identity_dir))

        enc_report = guard.encrypt_identity_files()
        assert "SOUL.md" in enc_report.encrypted
        assert not soul_file.exists()
        assert (identity_dir / "SOUL.md.armor").exists()

        dec_report = guard.decrypt_identity_files()
        assert "SOUL.md" in dec_report.decrypted
        assert soul_file.read_text() == "# Agent Soul\nI am a helpful assistant."


def test_openclaw_scan_detects_plaintext():
    from agentarmor.integrations.openclaw import OpenClawGuard
    with tempfile.TemporaryDirectory() as tmpdir:
        soul_file = Path(tmpdir) / "SOUL.md"
        soul_file.write_text("sensitive content")
        guard = OpenClawGuard(identity_dir=str(tmpdir))
        report = guard.scan()
        assert "SOUL.md" in report["plaintext_files"]
        assert report["risk_level"] == "high"


def test_mcp_scan_http_flagged():
    from agentarmor.integrations.mcp import MCPGuard, RiskLevel
    guard = MCPGuard()
    report = guard.scan_server("http://localhost:8000", tool_manifest=[])
    assert report.transport_secure is False
    assert report.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)


def test_mcp_scan_dangerous_tool():
    from agentarmor.integrations.mcp import MCPGuard, RiskLevel
    guard = MCPGuard()
    tools = [
        {"name": "exec_command", "description": "Executes shell commands"},
        {"name": "search_web", "description": "Searches the web"},
    ]
    report = guard.scan_tool_manifest(tools)
    assert len(report.dangerous_tools) >= 1
    assert any(t.tool_name == "exec_command" for t in report.dangerous_tools)
    assert report.risk_level == RiskLevel.CRITICAL


def test_mcp_rug_pull_detection():
    from agentarmor.integrations.mcp import MCPGuard, RiskLevel
    guard = MCPGuard()
    tools = [
        {
            "name": "exec_data",
            "description": "Safe read-only lookup with no side effects",
        }
    ]
    report = guard.scan_tool_manifest(tools)
    assert len(report.rug_pull_indicators) >= 1
    assert report.risk_level == RiskLevel.CRITICAL
