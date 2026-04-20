"""Layer 2: Memory & Storage Security — encryption at rest, classification, integrity."""
from __future__ import annotations

import os
import time
from typing import Any

import blake3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import StorageConfig
from agentarmor.core.exceptions import EncryptionError
from agentarmor.core.types import AgentEvent, DataClassification, LayerResult, SecurityVerdict, ThreatLevel


class EncryptionManager:
    def __init__(self, key: bytes | None = None, key_env: str = "AGENTARMOR_ENCRYPTION_KEY"):
        if key:
            self._key = key
        else:
            key_hex = os.environ.get(key_env, "")
            if not key_hex:
                self._key = AESGCM.generate_key(bit_length=256)
            else:
                self._key = bytes.fromhex(key_hex)
        if len(self._key) != 32:
            raise EncryptionError(f"Key must be 32 bytes, got {len(self._key)}")
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, token: bytes, associated_data: bytes | None = None) -> bytes:
        if len(token) < 12:
            raise EncryptionError("Invalid token: too short")
        nonce, ciphertext = token[:12], token[12:]
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}") from e

    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def generate_key_hex() -> str:
        return AESGCM.generate_key(bit_length=256).hex()


class IntegrityChecker:
    @staticmethod
    def compute(data: bytes) -> str:
        return blake3.blake3(data).hexdigest()

    @staticmethod
    def verify(data: bytes, expected_hash: str) -> bool:
        return blake3.blake3(data).hexdigest() == expected_hash


class DataClassifier:
    PII_KEYWORDS = {
        DataClassification.RESTRICTED: ["ssn", "social security", "passport", "credit card", "bank account"],
        DataClassification.CONFIDENTIAL: ["salary", "medical", "password", "secret", "private key", "api key"],
        DataClassification.INTERNAL: ["internal", "employee", "revenue", "strategy"],
    }

    @classmethod
    def classify(cls, text: str, metadata: dict[str, Any] | None = None) -> DataClassification:
        text_lower = text.lower()
        if metadata and metadata.get("classification"):
            try:
                return DataClassification(metadata["classification"])
            except ValueError:
                pass
        for level, keywords in cls.PII_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return level
        return DataClassification.PUBLIC


class StorageLayer(SecurityLayer):
    name = "L2_storage"

    def __init__(self, config: StorageConfig | None = None):
        self.config = config or StorageConfig()
        self.encryption = EncryptionManager(key_env=self.config.encryption_key_env) if self.config.encryption else None
        self.integrity = IntegrityChecker()
        self.classifier = DataClassifier()

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")
        findings: list[str] = []
        namespace = event.params.get("namespace", event.metadata.get("namespace", "default"))
        if self.config.allowed_namespaces and namespace not in self.config.allowed_namespaces:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.HIGH,
                message=f"Namespace '{namespace}' not allowed")
        if self.config.classification_required and event.input_data:
            text = str(event.input_data)
            classification = self.classifier.classify(text, event.metadata)
            event.metadata["classification"] = classification.value
            if classification in (DataClassification.RESTRICTED, DataClassification.TOP_SECRET):
                findings.append(f"Data classified as {classification.value}")
        if event.event_type in ("memory_read", "rag_retrieve"):
            stored_hash = event.metadata.get("integrity_hash", "")
            if stored_hash and event.input_data:
                data_bytes = event.input_data if isinstance(event.input_data, bytes) else str(event.input_data).encode()
                if not self.integrity.verify(data_bytes, stored_hash):
                    return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.CRITICAL,
                        message="Integrity check failed — data may have been tampered")
        if self.config.ttl_seconds:
            created_at = event.metadata.get("created_at", 0)
            if created_at and (time.time() - created_at) > self.config.ttl_seconds:
                return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.MEDIUM,
                    message="Data expired (TTL exceeded)")
        if findings:
            return LayerResult(
                layer=self.name, verdict=SecurityVerdict.AUDIT,
                threat_level=ThreatLevel.LOW, message="; ".join(findings),
            )
        return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Storage check passed")

    def encrypt_for_storage(self, data: bytes, namespace: str = "default") -> tuple[bytes, str]:
        if not self.encryption:
            raise EncryptionError("Encryption not configured")
        integrity = self.integrity.compute(data)
        encrypted = self.encryption.encrypt(data, associated_data=namespace.encode())
        return encrypted, integrity

    def decrypt_from_storage(self, encrypted: bytes, namespace: str = "default", expected_hash: str = "") -> bytes:
        if not self.encryption:
            raise EncryptionError("Encryption not configured")
        plaintext = self.encryption.decrypt(encrypted, associated_data=namespace.encode())
        if expected_hash and not self.integrity.verify(plaintext, expected_hash):
            raise EncryptionError("Integrity verification failed after decryption")
        return plaintext
