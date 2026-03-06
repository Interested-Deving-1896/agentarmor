"""Storage encryption example — encrypt/decrypt data for vector DB storage."""

from agentarmor.layers.storage.encryption import EncryptionManager, IntegrityChecker


def main():
    # Generate a key (do this once, store securely)
    key = EncryptionManager.generate_key()
    print(f"Generated key: {key.hex()}")

    # Create the encryption manager
    mgr = EncryptionManager(key=key)

    # Encrypt data before storing in vector DB
    document = "This is a sensitive RAG document with PII: John Smith, SSN 123-45-6789"
    namespace = "confidential-docs"

    encrypted = mgr.encrypt(
        document.encode("utf-8"),
        associated_data=namespace.encode("utf-8"),
    )
    print(f"\nEncrypted ({len(encrypted)} bytes): {encrypted[:50].hex()}...")

    # Compute integrity hash
    integrity_hash = IntegrityChecker.compute(document.encode("utf-8"))
    print(f"Integrity hash: {integrity_hash}")

    # Later: decrypt from vector DB
    decrypted = mgr.decrypt(encrypted, associated_data=namespace.encode("utf-8"))
    print(f"\nDecrypted: {decrypted.decode('utf-8')}")

    # Verify integrity
    is_valid = IntegrityChecker.verify(decrypted, integrity_hash)
    print(f"Integrity valid: {is_valid}")


if __name__ == "__main__":
    main()
