"""OpenClaw Guard example — encrypt and protect agent identity files."""

import tempfile
from pathlib import Path

from agentarmor import OpenClawGuard


def main():
    # Create a temporary directory simulating an OpenClaw identity store
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_dir = Path(tmpdir)

        # Simulate plaintext OpenClaw identity files
        (identity_dir / "SOUL.md").write_text(
            "# Agent Soul\n\n"
            "I am a financial assistant. I help users manage their budgets,\n"
            "track expenses, and provide investment advice.\n"
        )
        (identity_dir / "MEMORY.md").write_text(
            "# Agent Memory\n\n"
            "- User prefers conservative investments\n"
            "- User has 3 bank accounts\n"
            "- Last session: reviewed Q4 spending\n"
        )
        (identity_dir / "USER.md").write_text(
            "# User Profile\n\n"
            "Name: Jane Doe\n"
            "Risk tolerance: Low\n"
            "Preferred currency: USD\n"
        )

        print("=" * 60)
        print("OpenClaw Identity Guard — Example")
        print("=" * 60)

        # 1. Initialize the guard
        guard = OpenClawGuard(identity_dir=str(identity_dir))

        # 2. Scan — see what's at risk (read-only)
        print("\n--- SCAN (read-only audit) ---")
        scan_report = guard.scan()
        print(f"Directory:       {scan_report['directory']}")
        print(f"Exists:          {scan_report['exists']}")
        print(f"Risk level:      {scan_report['risk_level']}")
        print(f"Plaintext files: {scan_report['plaintext_files']}")
        print(f"Encrypted files: {scan_report['encrypted_files']}")

        # 3. Encrypt — protect the files
        print("\n--- ENCRYPT ---")
        enc_report = guard.encrypt_identity_files()
        print(enc_report.summary())
        print(f"Success: {enc_report.success}")

        # Verify plaintext is gone
        print("\nFiles after encryption:")
        for f in sorted(identity_dir.iterdir()):
            print(f"  {f.name} ({f.stat().st_size} bytes)")

        # 4. Scan again — should show low risk now
        print("\n--- SCAN (after encryption) ---")
        scan_report = guard.scan()
        print(f"Risk level:      {scan_report['risk_level']}")
        print(f"Plaintext files: {scan_report['plaintext_files']}")
        print(f"Encrypted files: {scan_report['encrypted_files']}")

        # 5. Decrypt — restore for debugging
        print("\n--- DECRYPT (restore plaintext) ---")
        dec_report = guard.decrypt_identity_files()
        print(f"Decrypted: {dec_report.decrypted}")
        print(f"Success:   {dec_report.success}")

        # Verify content is intact
        soul = (identity_dir / "SOUL.md").read_text()
        print(f"\nSOUL.md content preserved: {soul.startswith('# Agent Soul')}")


if __name__ == "__main__":
    main()
