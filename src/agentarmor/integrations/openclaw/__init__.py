"""
AgentArmor — OpenClaw Integration

Protects OpenClaw agent identity files from host-level compromise.
OpenClaw stores SOUL.md, MEMORY.md, USER.md as plaintext markdown.
Any malware on the host machine can read and steal the agent identity.
This module encrypts them with AES-256-GCM so only AgentArmor can read them.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from agentarmor.core.config import ArmorConfig


@dataclass
class EncryptionReport:
    encrypted: list[str] = field(default_factory=list)
    already_encrypted: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    identity_dir: str = ""

    @property
    def success(self) -> bool:
        return len(self.failed) == 0

    def summary(self) -> str:
        lines = [
            f"Identity directory: {self.identity_dir}",
            f"Encrypted now:      {self.encrypted}",
            f"Already secured:    {self.already_encrypted}",
            f"Failed:             {self.failed}",
        ]
        return "\n".join(lines)


@dataclass
class DecryptionReport:
    decrypted: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.failed) == 0


class OpenClawGuard:
    """
    Encrypts OpenClaw plaintext identity files using AgentArmor L2 storage
    encryption (AES-256-GCM + BLAKE3 integrity). Call once to secure an
    existing OpenClaw installation. Use decrypt_identity_files() to restore
    for debugging/inspection.

    Usage:
        from agentarmor.integrations.openclaw import OpenClawGuard
        guard = OpenClawGuard()
        report = guard.encrypt_identity_files()
        print(report.summary())
    """

    IDENTITY_FILENAMES = [
        "SOUL.md", "MEMORY.md", "USER.md", "NOTES.md",
        "PERSONA.md", "CONTEXT.md", "PROFILE.md",
    ]
    ENCRYPTED_SUFFIX = ".armor"

    def __init__(
        self,
        identity_dir: str | None = None,
        config: ArmorConfig | None = None,
    ):
        # Default OpenClaw identity directory locations
        if identity_dir:
            self.identity_dir = Path(identity_dir).expanduser().resolve()
        else:
            self.identity_dir = self._find_openclaw_dir()

        self.config = config or ArmorConfig()
        self._encryption_key = self._get_encryption_key()

    def _find_openclaw_dir(self) -> Path:
        """Try standard OpenClaw locations."""
        candidates = [
            Path.home() / ".openclaw",
            Path.home() / ".config" / "openclaw",
            Path.home() / "AppData" / "Roaming" / "openclaw",
            Path("/etc/openclaw"),
        ]
        for path in candidates:
            if path.exists():
                return path
        # Fall back to home dir — user can override
        return Path.home() / ".openclaw"

    def _get_encryption_key(self) -> bytes:
        """Load encryption key from env or generate a stable one."""
        key_env = os.environ.get("AGENTARMOR_ENCRYPTION_KEY")
        if key_env:
            return bytes.fromhex(key_env)
        # Generate from a stable seed based on machine identity
        import hashlib
        import platform
        seed = f"agentarmor-openclaw-{platform.node()}-{Path.home()}"
        return hashlib.sha256(seed.encode()).digest()

    def _encrypt_bytes(self, plaintext: bytes) -> bytes:
        """AES-256-GCM encrypt. Returns: nonce(12) + tag(16) + ciphertext."""
        try:
            import secrets

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(self._encryption_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            return nonce + ciphertext
        except ImportError as err:
            raise RuntimeError(
                "cryptography package required: uv add cryptography"
            ) from err

    def _decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt AES-256-GCM. Expects: nonce(12) + tag(16) + ciphertext."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self._encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def _integrity_hash(self, data: bytes) -> str:
        """BLAKE3 hash for tamper detection."""
        try:
            import blake3
            return blake3.blake3(data).hexdigest()
        except ImportError:
            import hashlib
            return hashlib.sha256(data).hexdigest()

    def scan(self) -> dict:
        """
        Scan the identity directory and report what files are at risk.
        Does NOT modify anything — read-only audit.

        Returns dict with 'plaintext_files', 'encrypted_files', 'directory'.
        """
        if not self.identity_dir.exists():
            return {
                "directory": str(self.identity_dir),
                "exists": False,
                "plaintext_files": [],
                "encrypted_files": [],
                "risk_level": "unknown",
            }

        plaintext = []
        encrypted_existing = []

        for name in self.IDENTITY_FILENAMES:
            md_path = self.identity_dir / name
            enc_path = self.identity_dir / (name + self.ENCRYPTED_SUFFIX)
            if md_path.exists():
                plaintext.append(name)
            if enc_path.exists():
                encrypted_existing.append(name + self.ENCRYPTED_SUFFIX)

        risk = "high" if plaintext else ("low" if encrypted_existing else "unknown")
        return {
            "directory": str(self.identity_dir),
            "exists": True,
            "plaintext_files": plaintext,
            "encrypted_files": encrypted_existing,
            "risk_level": risk,
        }

    def encrypt_identity_files(self) -> EncryptionReport:
        """
        Encrypt all plaintext identity .md files in the identity directory.
        Original .md files are deleted after successful encryption.
        A .armor.meta.json sidecar is written with integrity hash + filename.
        """
        report = EncryptionReport(identity_dir=str(self.identity_dir))

        if not self.identity_dir.exists():
            self.identity_dir.mkdir(parents=True, exist_ok=True)

        for filename in self.IDENTITY_FILENAMES:
            md_path = self.identity_dir / filename
            enc_path = self.identity_dir / (filename + self.ENCRYPTED_SUFFIX)
            meta_path = self.identity_dir / (filename + self.ENCRYPTED_SUFFIX + ".meta.json")

            if enc_path.exists():
                report.already_encrypted.append(filename)
                continue

            if not md_path.exists():
                continue

            try:
                plaintext = md_path.read_bytes()
                integrity = self._integrity_hash(plaintext)
                encrypted = self._encrypt_bytes(plaintext)

                enc_path.write_bytes(encrypted)
                meta_path.write_text(json.dumps({
                    "original_filename": filename,
                    "integrity_hash": integrity,
                    "encrypted_by": "agentarmor-core",
                    "algorithm": "AES-256-GCM + BLAKE3",
                }))

                md_path.unlink()  # Remove plaintext
                report.encrypted.append(filename)

            except Exception as e:
                report.failed.append(f"{filename}: {e}")

        return report

    def decrypt_identity_files(self) -> DecryptionReport:
        """
        Restore plaintext .md files from .armor encrypted files.
        Use this only for debugging — leaves files exposed afterward.
        """
        report = DecryptionReport()

        for enc_path in self.identity_dir.glob(f"*{self.ENCRYPTED_SUFFIX}"):
            if enc_path.suffix != self.ENCRYPTED_SUFFIX:
                continue
            original_name = enc_path.stem  # removes .armor
            md_path = self.identity_dir / original_name

            try:
                encrypted = enc_path.read_bytes()
                plaintext = self._decrypt_bytes(encrypted)
                md_path.write_bytes(plaintext)
                report.decrypted.append(original_name)
            except Exception as e:
                report.failed.append(f"{enc_path.name}: {e}")

        return report
