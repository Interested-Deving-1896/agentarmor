import os
import json
import base64
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class L2DecryptionError(Exception):
    """Raised when AES-GCM tag authentication fails, indicating corruption or tampering."""
    pass

def encrypt_field(plaintext: str, key: bytes) -> str:
    """
    AES-256-GCM encrypt a string field for database storage.
    Returns base64-encoded nonce + ciphertext (URL-safe) prefixed with 'AA2:'.
    """
    nonce = os.urandom(12)  # 96-bit nonce, NEVER reused for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    
    # Store nonce prepended to the ciphertext
    encoded = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return f"AA2:{encoded}"


def decrypt_field(value: str, key: bytes) -> str:
    """
    Decrypt an AES-256-GCM field. Raises L2DecryptionError if tampered.
    """
    if not is_encrypted(value):
        raise ValueError("Cannot decrypt: Value does not have 'AA2:' prefix.")
    
    # Strip the AA2: prefix
    raw_b64 = value[4:]
    raw = base64.urlsafe_b64decode(raw_b64)
    
    # Split the 12-byte nonce and ciphertext
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    
    try:
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
    except InvalidTag as e:
        raise L2DecryptionError("Memory Tampering Detected: Authenticated Decryption Failed.") from e


def compute_mac(data: dict, key: bytes) -> str:
    """
    Compute an HMAC over immutable fields of an event or message to detect retroactive tampering.
    Uses canonical JSON (sorted keys) for deterministic representation.
    """
    canonical = json.dumps(data, sort_keys=True).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def verify_mac(data: dict, stored_mac: str, key: bytes) -> bool:
    """Constant-time MAC comparison."""
    if not stored_mac:
        return False
    expected = compute_mac(data, key)
    return hmac.compare_digest(expected, stored_mac)


def is_encrypted(value: str | None) -> bool:
    """Returns True if the value matches the L2 encryption schema prefix."""
    return value is not None and isinstance(value, str) and value.startswith("AA2:")
