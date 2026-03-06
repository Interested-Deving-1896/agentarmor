"""AgentArmor CLI — command-line interface for configuration, scanning, and proxy server."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from agentarmor.core.config import ArmorConfig


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize a new AgentArmor configuration."""
    config = ArmorConfig(agent_type=args.agent_type, risk_level=args.risk_level)
    output = Path(args.output)
    config.to_yaml(output)
    print(f"Created configuration: {output}")


def cmd_validate(args: argparse.Namespace) -> None:
    """Validate a configuration or policy file."""
    path = Path(args.config)
    try:
        config = ArmorConfig.from_yaml(path)
        print(f"Configuration valid: {path}")
        print(f"  Agent type: {config.agent_type}")
        print(f"  Risk level: {config.risk_level}")
        print(f"  Layers enabled: {sum(1 for l in [config.ingestion, config.storage, config.context, config.planning, config.execution, config.output, config.interagent, config.identity] if l.enabled)}/8")
    except Exception as e:
        print(f"Validation failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_scan(args: argparse.Namespace) -> None:
    """Scan input text for security issues."""
    from agentarmor import AgentArmor, AgentEvent, ArmorConfig

    config = ArmorConfig()
    if args.config:
        config = ArmorConfig.from_yaml(args.config)

    armor = AgentArmor(config=config)
    text = args.text or sys.stdin.read()

    event = AgentEvent(
        agent_id="cli-scanner",
        event_type="scan",
        action="cli.scan",
        input_data=text,
    )

    result = asyncio.run(armor.process(event))
    output = {
        "verdict": result.final_verdict.value,
        "threat_level": result.final_threat_level.value,
        "blocked_by": result.blocked_by,
        "layers": [
            {
                "layer": lr.layer,
                "verdict": lr.verdict.value,
                "threat_level": lr.threat_level.value,
                "message": lr.message,
                "time_ms": round(lr.processing_time_ms, 2),
            }
            for lr in result.layer_results
        ],
    }
    print(json.dumps(output, indent=2))


def cmd_serve(args: argparse.Namespace) -> None:
    """Start the AgentArmor proxy server."""
    try:
        from agentarmor.proxy.server import create_app
        import uvicorn
    except ImportError:
        print("Proxy dependencies not installed. Run: uv add 'agentarmor[proxy]'", file=sys.stderr)
        sys.exit(1)

    config = ArmorConfig.from_yaml(args.config) if args.config else ArmorConfig()
    app = create_app(config)
    uvicorn.run(app, host=args.host, port=args.port)


def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate an encryption key."""
    from agentarmor.layers.storage.encryption import EncryptionManager
    key = EncryptionManager.generate_key_hex()
    print(f"Generated 256-bit encryption key:")
    print(f"  Hex: {key}")
    print(f"\nSet as environment variable:")
    print(f"  export AGENTARMOR_ENCRYPTION_KEY={key}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agentarmor",
        description="AgentArmor — Security framework for agentic AI applications",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize configuration")
    p_init.add_argument("-o", "--output", default="agentarmor.yaml")
    p_init.add_argument("--agent-type", default="general")
    p_init.add_argument("--risk-level", default="medium", choices=["low", "medium", "high", "critical"])
    p_init.set_defaults(func=cmd_init)

    # validate
    p_val = subparsers.add_parser("validate", help="Validate configuration")
    p_val.add_argument("config", help="Path to YAML config file")
    p_val.set_defaults(func=cmd_validate)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan text for security issues")
    p_scan.add_argument("--text", "-t", help="Text to scan (or pipe via stdin)")
    p_scan.add_argument("--config", "-c", help="Config file path")
    p_scan.set_defaults(func=cmd_scan)

    # serve
    p_serve = subparsers.add_parser("serve", help="Start proxy server")
    p_serve.add_argument("--config", "-c", help="Config file path")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8400)
    p_serve.set_defaults(func=cmd_serve)

    # keygen
    p_key = subparsers.add_parser("keygen", help="Generate encryption key")
    p_key.set_defaults(func=cmd_keygen)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
