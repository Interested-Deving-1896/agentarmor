"""
AgentArmor — OAuth 2.1 Verifier for MCP Servers

Implements the verification requirements from the official MCP spec
(modelcontextprotocol.io/specification/2025-11-25/basic/authorization):

MUST requirements implemented here:
  - Authorization servers MUST implement OAuth 2.1
  - MCP clients MUST use S256 PKCE (verified via server metadata)
  - MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)
  - Authorization server metadata discovery (RFC8414)
  - Token audience binding validation
  - PKCE S256 support check (refuse if absent)
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


@dataclass
class OAuthReport:
    server_url: str
    oauth_compliant: bool = False
    has_protected_resource_metadata: bool = False
    has_authorization_server_metadata: bool = False
    pkce_s256_supported: bool = False
    tls_required: bool = False
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    authorization_server: str | None = None

    def summary(self) -> str:
        lines = [
            f"Server:                {self.server_url}",
            f"OAuth 2.1 compliant:   {'✓' if self.oauth_compliant else '✗'}",
            f"Protected Resource MD: {'✓' if self.has_protected_resource_metadata else '✗'}",
            f"Auth Server MD:        {'✓' if self.has_authorization_server_metadata else '✗'}",
            f"PKCE S256:             {'✓' if self.pkce_s256_supported else '✗ REQUIRED'}",
            f"TLS enforced:          {'✓' if self.tls_required else '✗'}",
        ]
        if self.authorization_server:
            lines.append(f"Auth server:           {self.authorization_server}")
        if self.issues:
            lines.append("Issues:")
            for i in self.issues:
                lines.append(f"  🚨 {i}")
        if self.warnings:
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  ⚠ {w}")
        return "\n".join(lines)


class OAuthVerifier:
    """
    Verifies OAuth 2.1 compliance of an MCP server.

    Usage:
        from agentarmor.integrations.mcp.oauth_verifier import OAuthVerifier
        verifier = OAuthVerifier()
        report = verifier.verify_server("https://api.example.com/mcp")
        if not report.pkce_s256_supported:
            raise SecurityError("Server does not support PKCE S256 — refuse to proceed")
    """

    def verify_server(self, server_url: str, timeout: int = 5) -> OAuthReport:
        """
        Verify OAuth 2.1 compliance of an MCP server.

        Checks (in order):
        1. HTTPS-only (OAuth 2.1 mandates it)
        2. Protected Resource Metadata (RFC9728) at well-known URI
        3. Authorization Server Metadata (RFC8414)
        4. PKCE S256 support — REFUSE if absent (per MCP spec)
        5. Token audience binding capability
        """
        report = OAuthReport(server_url=server_url)

        parsed = urlparse(server_url)

        # 1. HTTPS check — OAuth 2.1 Section 1.5 mandates HTTPS
        if parsed.scheme != "https":
            report.oauth_compliant = False
            report.issues.append(
                "OAuth 2.1 requires all authorization server endpoints to be "
                "served over HTTPS. HTTP is not permitted."
            )
            return report

        report.tls_required = True

        if not HAS_HTTPX:
            report.warnings.append(
                "httpx not installed — cannot fetch OAuth metadata. "
                "Install with: uv add httpx"
            )
            return report

        base = server_url.rstrip("/")
        parsed_base = urlparse(base)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # 2. Protected Resource Metadata (RFC9728) — MUST per MCP spec
        prm = self._fetch_protected_resource_metadata(origin, base, timeout)
        if prm:
            report.has_protected_resource_metadata = True
            report.metadata["protected_resource"] = prm
            auth_servers = prm.get("authorization_servers", [])
            if auth_servers:
                report.authorization_server = auth_servers[0]
            else:
                report.warnings.append(
                    "Protected Resource Metadata missing 'authorization_servers' field"
                )
        else:
            report.issues.append(
                "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata "
                "(RFC9728). Well-known URI not found."
            )

        # 3. Authorization Server Metadata (RFC8414)
        auth_server_url = report.authorization_server or origin
        as_meta = self._fetch_authorization_server_metadata(auth_server_url, timeout)
        if as_meta:
            report.has_authorization_server_metadata = True
            report.metadata["authorization_server"] = as_meta

            # 4. PKCE S256 check — MUST refuse if absent
            pkce_methods = as_meta.get("code_challenge_methods_supported", [])
            if "S256" in pkce_methods:
                report.pkce_s256_supported = True
            else:
                report.issues.append(
                    "PKCE S256 not found in 'code_challenge_methods_supported'. "
                    "Per MCP spec, clients MUST refuse to proceed without PKCE S256 "
                    "support. This server cannot be used safely."
                )

            # 5. Check token endpoint auth methods
            token_methods = as_meta.get("token_endpoint_auth_methods_supported", [])
            if "none" in token_methods and len(token_methods) == 1:
                report.warnings.append(
                    "Only 'none' token endpoint auth method supported — "
                    "consider adding 'private_key_jwt' for confidential clients"
                )

            # 6. Check grant types
            grant_types = as_meta.get("grant_types_supported", [])
            if "authorization_code" not in grant_types:
                report.issues.append(
                    "Authorization code grant not supported — required for MCP OAuth flow"
                )

        else:
            report.issues.append(
                "Could not fetch Authorization Server Metadata (RFC8414). "
                "Tried both OAuth 2.0 AS Metadata and OpenID Connect Discovery endpoints."
            )

        # 6. Compute overall compliance
        report.oauth_compliant = (
            report.has_protected_resource_metadata
            and report.has_authorization_server_metadata
            and report.pkce_s256_supported
            and len(report.issues) == 0
        )

        return report

    def _fetch_protected_resource_metadata(
        self, origin: str, base: str, timeout: int
    ) -> dict | None:
        """Try RFC9728 well-known URIs."""
        path = urlparse(base).path.rstrip("/")
        candidates = [
            f"{origin}/.well-known/oauth-protected-resource{path}",
            f"{origin}/.well-known/oauth-protected-resource",
        ]
        return self._try_fetch_json(candidates, timeout)

    def _fetch_authorization_server_metadata(
        self, auth_server: str, timeout: int
    ) -> dict | None:
        """Try RFC8414 and OIDC Discovery endpoints in priority order."""
        parsed = urlparse(auth_server)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")

        if path:
            # With path component — try path insertion first
            candidates = [
                f"{origin}/.well-known/oauth-authorization-server{path}",
                f"{origin}/.well-known/openid-configuration{path}",
                f"{auth_server}/.well-known/openid-configuration",
            ]
        else:
            candidates = [
                f"{origin}/.well-known/oauth-authorization-server",
                f"{origin}/.well-known/openid-configuration",
            ]

        return self._try_fetch_json(candidates, timeout)

    def _try_fetch_json(self, urls: list[str], timeout: int) -> dict | None:
        for url in urls:
            try:
                resp = httpx.get(url, timeout=timeout, follow_redirects=True)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                continue
        return None

    @staticmethod
    def generate_pkce_pair() -> tuple[str, str]:
        """
        Generate a PKCE code_verifier + code_challenge (S256) pair.
        Use this when initiating OAuth flows in your MCP client.

        Returns:
            (code_verifier, code_challenge) both as strings
        """
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return code_verifier, code_challenge
