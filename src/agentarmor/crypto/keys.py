import os
import platform
import uuid
import hashlib
import logging
from pathlib import Path

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

# Fallback wrapper for Argon2
try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    logger.warning("argon2-cffi not installed. Falling back to PBKDF2-HMAC-SHA256 for L2 Storage Key Derivation. Upgrade recommended for security.")

# Singletons
_MASTER_KEY: bytes | None = None
AGENTARMOR_DIR = Path.home() / ".agentarmor"


def get_machine_fingerprint() -> bytes:
    """Generate a stable machine-specific identifier."""
    components = []
    
    try:
        if platform.system() == "Darwin":
            import subprocess
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True
            )
            uuid_line = [l for l in result.stdout.split("\n") if "IOPlatformUUID" in l]
            if uuid_line:
                components.append(uuid_line[0].split('"')[-2])
        elif platform.system() == "Windows":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            components.append(machine_guid)
        else:
            with open("/etc/machine-id") as f:
                components.append(f.read().strip())
    except Exception as e:
        logger.debug(f"Failed to get hardware fingerprint: {e}")
    
    # Always include a fallback file UUID so we are guaranteed entropy even on permission failures
    fallback_path = AGENTARMOR_DIR / "machine.id"
    if not fallback_path.exists():
        AGENTARMOR_DIR.mkdir(parents=True, exist_ok=True)
        fallback_path.write_text(str(uuid.uuid4()))
        if platform.system() != "Windows":
            os.chmod(fallback_path, 0o600)
    components.append(fallback_path.read_text().strip())

    combined = ":".join(components).encode("utf-8")
    return hashlib.sha256(combined).digest()


def derive_master_key(salt: bytes) -> bytes:
    """Derive the 32-byte AES-256 master key."""
    password = get_machine_fingerprint()
    
    if ARGON2_AVAILABLE:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=2,
            memory_cost=65536,
            parallelism=2,
            hash_len=32,
            type=Type.ID
        )
    else:
        # Graceful fallback: NIST recommended 600,000 iterations PBKDF2
        return hashlib.pbkdf2_hmac('sha256', password, salt, 600000, 32)


def get_or_create_master_key() -> bytes:
    """Load or initialize the master encryption key for this installation."""
    AGENTARMOR_DIR.mkdir(parents=True, exist_ok=True)
    salt_path = AGENTARMOR_DIR / "install.salt"

    if not salt_path.exists():
        salt = os.urandom(32)
        salt_path.write_bytes(salt)
        if platform.system() != "Windows":
            os.chmod(salt_path, 0o600)
    else:
        salt = salt_path.read_bytes()

    return derive_master_key(salt)


def derive_child_key(master_key: bytes, context: bytes, agent_salt: bytes | None = None) -> bytes:
    """Secure key separation using HKDF."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=agent_salt,
        info=context,
    ).derive(master_key)


def _get_master_lazy() -> bytes:
    global _MASTER_KEY
    if _MASTER_KEY is None:
        _MASTER_KEY = get_or_create_master_key()
    return _MASTER_KEY


def get_db_key() -> bytes:
    """Key for encrypting studio.db contents (conversations, events)."""
    return derive_child_key(_get_master_lazy(), b"agentarmor-db-v1")


def get_api_key_key() -> bytes:
    """Key for encrypting API Keys before storing them."""
    return derive_child_key(_get_master_lazy(), b"agentarmor-api-v1")


def get_workspace_key(agent_id: str) -> bytes:
    """Key for encrypting the specific agent's workspace SQLite file."""
    agent_salt = hashlib.sha256(f"workspace:{agent_id}".encode("utf-8")).digest()
    return derive_child_key(_get_master_lazy(), b"agentarmor-ws-v1", agent_salt=agent_salt)
