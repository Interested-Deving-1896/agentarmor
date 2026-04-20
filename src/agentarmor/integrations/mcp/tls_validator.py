"""
AgentArmor — TLS Certificate Validator for MCP Servers

Implements strict TLS chain validation as required by the SlowMist
MCP Security Checklist and the official MCP specification:
  - TLS 1.2 minimum (TLS 1.3 preferred)
  - Full certificate chain validation (no self-signed certs in prod)
  - Hostname verification
  - Certificate expiry check
  - Weak cipher detection
"""
from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class TLSReport:
    hostname: str
    valid: bool = False
    tls_version: str | None = None
    cert_expiry: datetime.datetime | None = None
    days_until_expiry: int | None = None
    cipher_suite: str | None = None
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    cert_subject: str | None = None

    def summary(self) -> str:
        lines = [
            f"Host:           {self.hostname}",
            f"Valid:          {'✓' if self.valid else '✗'}",
            f"TLS version:    {self.tls_version or 'unknown'}",
            f"Cipher:         {self.cipher_suite or 'unknown'}",
            f"Cert expiry:    {self.cert_expiry.date() if self.cert_expiry else 'unknown'}",
            f"Days remaining: {self.days_until_expiry}",
        ]
        if self.issues:
            lines.append("Issues:")
            for i in self.issues:
                lines.append(f"  🚨 {i}")
        if self.warnings:
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  ⚠ {w}")
        return "\n".join(lines)


class TLSValidator:
    """
    Validates TLS configuration of MCP servers.
    Called by MCPGuard.scan_server() automatically for HTTPS URLs.

    Usage:
        from agentarmor.integrations.mcp.tls_validator import TLSValidator
        validator = TLSValidator()
        report = validator.validate_server("https://api.example.com")
        if not report.valid:
            raise SecurityError(report.issues)
    """

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL",
        "EXPORT", "anon", "ADH", "AECDH",
    ]
    MIN_TLS_VERSION = "TLSv1.2"
    CERT_EXPIRY_WARNING_DAYS = 30

    def validate_server(
        self,
        url: str,
        timeout: int = 5,
        allow_self_signed: bool = False,
    ) -> TLSReport:
        """
        Connect to server and validate its TLS configuration.

        Args:
            url: Full URL (https://...) or hostname
            timeout: Connection timeout seconds
            allow_self_signed: Set True only in local dev/testing
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or url.replace("https://", "").split("/")[0].split(":")[0]
        port = parsed.port or 443

        report = TLSReport(hostname=hostname)

        # Step 1: HTTP check — if not HTTPS, immediate fail
        if parsed.scheme == "http":
            report.valid = False
            report.issues.append(
                "HTTP transport — all data transmitted in plaintext. "
                "MCP spec requires HTTPS for all production servers."
            )
            return report

        # Step 2: Full TLS handshake with cert validation
        try:
            ctx = ssl.create_default_context()
            if allow_self_signed:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with (
                socket.create_connection((hostname, port), timeout=timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
            ):
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()

            report.tls_version = tls_version
            report.cipher_suite = cipher[0] if cipher else None

            # Step 3: TLS version check
            if tls_version == "TLSv1" or tls_version == "TLSv1.1":
                report.issues.append(
                    f"{tls_version} is deprecated and insecure. Minimum: TLS 1.2"
                )
            elif tls_version == self.MIN_TLS_VERSION:
                report.warnings.append("TLS 1.2 — upgrade to TLS 1.3 recommended")

            # Step 4: Cipher suite check
            if cipher and cipher[0]:
                for weak in self.WEAK_CIPHERS:
                    if weak in cipher[0].upper():
                        report.issues.append(
                            f"Weak cipher detected: {cipher[0]}. "
                            f"Disable {weak} cipher suites."
                        )

            # Step 5: Certificate expiry check
            if cert and "notAfter" in cert:
                expiry = ssl.cert_time_to_seconds(cert["notAfter"])
                expiry_dt = datetime.datetime.utcfromtimestamp(expiry)
                report.cert_expiry = expiry_dt
                days_left = (expiry_dt - datetime.datetime.utcnow()).days
                report.days_until_expiry = days_left
                if days_left <= 0:
                    report.issues.append(
                        f"Certificate EXPIRED {abs(days_left)} days ago"
                    )
                elif days_left <= self.CERT_EXPIRY_WARNING_DAYS:
                    report.warnings.append(
                        f"Certificate expires in {days_left} days — renew soon"
                    )

            # Step 6: Subject / SAN check
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                report.cert_subject = subject.get("commonName", "unknown")
                san = cert.get("subjectAltName", [])
                san_hostnames = [v for k, v in san if k == "DNS"]
                if san_hostnames and hostname not in san_hostnames:
                    # Check wildcards
                    wildcard_match = any(
                        h.startswith("*.") and hostname.endswith(h[1:])
                        for h in san_hostnames
                    )
                    if not wildcard_match:
                        report.issues.append(
                            f"Hostname {hostname!r} not in certificate SANs: {san_hostnames}"
                        )

            report.valid = len(report.issues) == 0

        except ssl.SSLCertVerificationError as e:
            report.valid = False
            report.issues.append(
                f"Certificate verification FAILED: {e}. "
                "Possible MITM attack or self-signed certificate."
            )
        except ssl.SSLError as e:
            report.valid = False
            report.issues.append(f"TLS handshake failed: {e}")
        except (TimeoutError, ConnectionRefusedError, OSError) as e:
            report.valid = False
            report.issues.append(f"Could not connect: {e}")

        return report
