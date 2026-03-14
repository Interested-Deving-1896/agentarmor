"""Tests for TLS validator and OAuth verifier — no live network required."""
import pytest
from unittest.mock import patch, MagicMock
import ssl, datetime


def test_tls_validator_rejects_http():
    from agentarmor.integrations.mcp.tls_validator import TLSValidator
    v = TLSValidator()
    report = v.validate_server("http://example.com")
    assert report.valid is False
    assert any("plaintext" in i.lower() or "http" in i.lower() for i in report.issues)


def test_tls_validator_detects_expired_cert():
    from agentarmor.integrations.mcp.tls_validator import TLSValidator
    v = TLSValidator()
    import unittest.mock as mock

    mock_cert = {
        "notAfter": "Jan  1 00:00:00 2020 GMT",
        "subject": [[("commonName", "example.com")]],
        "subjectAltName": [("DNS", "example.com")],
    }
    mock_cipher = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    with mock.patch("ssl.create_default_context") as mock_ctx:
        mock_ssock = mock.MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = mock_cipher
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = mock.MagicMock(return_value=False)

        mock_sock = mock.MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = mock.MagicMock(return_value=False)

        mock_ctx.return_value.wrap_socket.return_value = mock_ssock
        with mock.patch("socket.create_connection", return_value=mock_sock):
            report = v.validate_server("https://example.com")

    assert any("expir" in i.lower() for i in report.issues)
    assert report.valid is False


def test_tls_validator_flags_weak_cipher():
    from agentarmor.integrations.mcp.tls_validator import TLSValidator
    v = TLSValidator()
    import unittest.mock as mock

    future = datetime.datetime.utcnow() + datetime.timedelta(days=365)
    mock_cert = {
        "notAfter": future.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": [[("commonName", "example.com")]],
        "subjectAltName": [("DNS", "example.com")],
    }
    mock_cipher = ("RC4-SHA", "TLSv1.2", 128)

    with mock.patch("ssl.create_default_context") as mock_ctx:
        mock_ssock = mock.MagicMock()
        mock_ssock.version.return_value = "TLSv1.2"
        mock_ssock.cipher.return_value = mock_cipher
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__ = mock.MagicMock(return_value=False)
        mock_sock = mock.MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = mock.MagicMock(return_value=False)
        mock_ctx.return_value.wrap_socket.return_value = mock_ssock
        with mock.patch("socket.create_connection", return_value=mock_sock):
            report = v.validate_server("https://example.com")

    assert any("RC4" in i or "weak" in i.lower() for i in report.issues)


def test_oauth_verifier_rejects_http():
    from agentarmor.integrations.mcp.oauth_verifier import OAuthVerifier
    v = OAuthVerifier()
    report = v.verify_server("http://example.com/mcp")
    assert report.oauth_compliant is False
    assert any("https" in i.lower() for i in report.issues)


def test_oauth_verifier_pkce_missing_flagged():
    from agentarmor.integrations.mcp.oauth_verifier import OAuthVerifier
    import unittest.mock as mock

    prm_data = {"authorization_servers": ["https://auth.example.com"]}
    as_data = {
        "code_challenge_methods_supported": ["plain"],  # NO S256
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none"],
    }

    v = OAuthVerifier()
    with mock.patch.object(v, "_try_fetch_json", side_effect=[prm_data, as_data]):
        report = v.verify_server("https://example.com/mcp")

    assert report.pkce_s256_supported is False
    assert report.oauth_compliant is False
    assert any("s256" in i.lower() or "pkce" in i.lower() for i in report.issues)


def test_oauth_verifier_pkce_s256_passes():
    from agentarmor.integrations.mcp.oauth_verifier import OAuthVerifier
    import unittest.mock as mock

    prm_data = {"authorization_servers": ["https://auth.example.com"]}
    as_data = {
        "code_challenge_methods_supported": ["S256", "plain"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
    }

    v = OAuthVerifier()
    with mock.patch.object(v, "_try_fetch_json", side_effect=[prm_data, as_data]):
        report = v.verify_server("https://example.com/mcp")

    assert report.pkce_s256_supported is True
    assert report.has_protected_resource_metadata is True
    assert report.has_authorization_server_metadata is True
    assert len(report.issues) == 0


def test_pkce_pair_generation():
    from agentarmor.integrations.mcp.oauth_verifier import OAuthVerifier
    import hashlib, base64
    verifier, challenge = OAuthVerifier.generate_pkce_pair()

    # Verify S256: challenge = BASE64URL(SHA256(verifier))
    digest = hashlib.sha256(verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert challenge == expected
    assert len(verifier) >= 43   # RFC 7636 minimum


def test_mcp_guard_full_scan_http_is_high_risk():
    from agentarmor.integrations.mcp import MCPGuard
    guard = MCPGuard()
    result = guard.full_security_scan("http://localhost:8000", tool_manifest=[])
    assert result["overall_risk"] in ("high", "critical")
    assert result["passed"] is False or result["overall_risk"] == "medium"


def test_mcp_guard_full_scan_dangerous_tool():
    from agentarmor.integrations.mcp import MCPGuard
    from unittest.mock import patch
    guard = MCPGuard()
    tools = [{"name": "exec_shell", "description": "Execute shell commands"}]
    # Patch TLS + OAuth to pass so we isolate the tool risk
    with patch.object(guard.tls_validator, "validate_server") as mock_tls, \
         patch.object(guard.oauth_verifier, "verify_server") as mock_oauth:

        mock_tls.return_value = MagicMock(valid=True, issues=[], warnings=[])
        mock_oauth.return_value = MagicMock(
            oauth_compliant=True, pkce_s256_supported=True, issues=[], warnings=[]
        )
        result = guard.full_security_scan(
            "https://example.com", tool_manifest=tools
        )

    assert result["overall_risk"] == "critical"
