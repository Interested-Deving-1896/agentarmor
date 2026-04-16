"""Layer 7: Hardened Inter-Agent Communication Security.

Five hardening components:
  T1 — Replay Prevention (Nonce + Timestamp Registry)
  T2 — Delegation Chain Authorization (DelegationCertificate)
  T3 — Trust Score with Directed-Pair Decay
  T4 — Scope Binding
  T5 — Compromised Agent Detection (Behavioral Baseline)
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


# =============================================================================
# T1 — REPLAY PREVENTION
# =============================================================================

MAX_CLOCK_SKEW = 300  # seconds
NONCE_TTL = 600       # seconds
NONCE_CAP = 10_000


class VerifyResult(enum.Enum):
    ALLOW = "allow"
    REPLAY_EXPIRED = "replay_expired"
    REPLAY_DETECTED = "replay_detected"
    TAMPERED = "tampered"
    BLOCKED_LOW_TRUST = "blocked_low_trust"
    SCOPE_VIOLATION = "scope_violation"
    DELEGATION_DEPTH_EXCEEDED = "delegation_depth_exceeded"
    DELEGATION_EXPIRED = "delegation_expired"
    CERTIFICATE_TAMPERED = "certificate_tampered"
    ANOMALY_BLOCKED = "anomaly_blocked"
    FORBIDDEN_ACTION = "forbidden_action"


class NonceRegistry:
    """Thread-safe-ish nonce deduplication with TTL-based expiry."""

    def __init__(self) -> None:
        self._nonces: dict[str, float] = {}  # nonce → expiry_time

    def _sweep_expired(self) -> None:
        now = time.time()
        expired = [k for k, exp in self._nonces.items() if exp <= now]
        for k in expired:
            del self._nonces[k]

    def check_and_register(self, nonce: str) -> bool:
        """Return True if nonce is fresh. False if replayed or cap exceeded."""
        self._sweep_expired()

        if nonce in self._nonces:
            return False

        if len(self._nonces) >= NONCE_CAP:
            self._sweep_expired()
            if len(self._nonces) >= NONCE_CAP:
                return False  # Hard cap hit — reject

        self._nonces[nonce] = time.time() + NONCE_TTL
        return True

    @property
    def size(self) -> int:
        return len(self._nonces)


_nonce_registry = NonceRegistry()


def create_signed_payload(
    sender_id: str,
    receiver_id: str,
    action: str,
    body: dict[str, Any],
    shared_secret: str,
) -> dict[str, Any]:
    """Build an inter-agent message payload with timestamp + nonce + HMAC."""
    payload: dict[str, Any] = {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "action": action,
        "body": body,
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(16),
    }
    # HMAC covers the full payload (excluding signature field itself)
    sig_input = json.dumps(payload, sort_keys=True)
    payload["signature"] = hmac.new(
        shared_secret.encode(), sig_input.encode(), hashlib.sha256
    ).hexdigest()
    return payload


def verify_message(
    payload: dict[str, Any],
    shared_secret: str,
) -> VerifyResult:
    """Verify timestamp freshness → nonce uniqueness → HMAC."""
    ts = payload.get("timestamp", 0)
    nonce = payload.get("nonce", "")
    signature = payload.pop("signature", "")

    # Reconstruct the signing input (without signature)
    sig_input = json.dumps(payload, sort_keys=True)
    payload["signature"] = signature  # Put it back

    # 1. Timestamp freshness
    if abs(time.time() - ts) > MAX_CLOCK_SKEW:
        return VerifyResult.REPLAY_EXPIRED

    # 2. Nonce uniqueness
    if not _nonce_registry.check_and_register(nonce):
        return VerifyResult.REPLAY_DETECTED

    # 3. HMAC
    expected = hmac.new(
        shared_secret.encode(), sig_input.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return VerifyResult.TAMPERED

    return VerifyResult.ALLOW


# =============================================================================
# T2 — DELEGATION CHAIN AUTHORIZATION
# =============================================================================

DEFAULT_MAX_DEPTH = 3
MAX_CERT_TTL = 3600  # 1 hour


@dataclass
class DelegationCertificate:
    delegator_id: str
    delegate_id: str
    authorized_scope: list[str]
    max_depth: int = DEFAULT_MAX_DEPTH
    current_depth: int = 0
    expires_at: float = 0.0
    task_description: str = ""
    certificate_id: str = field(default_factory=lambda: secrets.token_hex(16))
    signature: str = ""

    def sign(self, shared_secret: str) -> None:
        """Sign the certificate with HMAC over all fields except signature."""
        obj = {
            "delegator_id": self.delegator_id,
            "delegate_id": self.delegate_id,
            "authorized_scope": sorted(self.authorized_scope),
            "max_depth": self.max_depth,
            "current_depth": self.current_depth,
            "expires_at": self.expires_at,
            "task_description": self.task_description,
            "certificate_id": self.certificate_id,
        }
        sig_input = json.dumps(obj, sort_keys=True)
        self.signature = hmac.new(
            shared_secret.encode(), sig_input.encode(), hashlib.sha256
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "delegator_id": self.delegator_id,
            "delegate_id": self.delegate_id,
            "authorized_scope": self.authorized_scope,
            "max_depth": self.max_depth,
            "current_depth": self.current_depth,
            "expires_at": self.expires_at,
            "task_description": self.task_description,
            "certificate_id": self.certificate_id,
            "signature": self.signature,
        }


def create_delegation(
    delegator_id: str,
    delegate_id: str,
    scope: list[str],
    shared_secret: str,
    max_depth: int = DEFAULT_MAX_DEPTH,
    ttl_seconds: int = MAX_CERT_TTL,
    task_description: str = "",
) -> DelegationCertificate:
    cert = DelegationCertificate(
        delegator_id=delegator_id,
        delegate_id=delegate_id,
        authorized_scope=scope,
        max_depth=max_depth,
        current_depth=0,
        expires_at=time.time() + min(ttl_seconds, MAX_CERT_TTL),
        task_description=task_description,
    )
    cert.sign(shared_secret)
    return cert


def verify_delegated_action(
    action: str,
    cert: DelegationCertificate,
    shared_secret: str,
) -> VerifyResult:
    """Check delegation certificate: expiry → depth → scope → HMAC."""
    # 1. Expiry
    if cert.expires_at <= time.time():
        return VerifyResult.DELEGATION_EXPIRED

    # 2. Depth
    if cert.current_depth > cert.max_depth:
        return VerifyResult.DELEGATION_DEPTH_EXCEEDED

    # 3. Scope
    if action not in cert.authorized_scope:
        # Support wildcard matching
        scope_match = False
        for scope_item in cert.authorized_scope:
            if scope_item == "*":
                scope_match = True
                break
            if scope_item.endswith("*") and action.startswith(scope_item[:-1]):
                scope_match = True
                break
        if not scope_match:
            return VerifyResult.SCOPE_VIOLATION

    # 4. Certificate signature
    obj = {
        "delegator_id": cert.delegator_id,
        "delegate_id": cert.delegate_id,
        "authorized_scope": sorted(cert.authorized_scope),
        "max_depth": cert.max_depth,
        "current_depth": cert.current_depth,
        "expires_at": cert.expires_at,
        "task_description": cert.task_description,
        "certificate_id": cert.certificate_id,
    }
    sig_input = json.dumps(obj, sort_keys=True)
    expected = hmac.new(
        shared_secret.encode(), sig_input.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, cert.signature):
        return VerifyResult.CERTIFICATE_TAMPERED

    return VerifyResult.ALLOW


# =============================================================================
# T3 — TRUST SCORING (PER DIRECTED PAIR)
# =============================================================================

# Event deltas
TRUST_DELTAS: dict[str, float] = {
    "MESSAGE_VERIFIED": +0.02,
    "SCOPE_HONORED": +0.03,
    "REPLAY_DETECTED": -0.30,
    "HMAC_FAILURE": -0.20,
    "SCOPE_VIOLATION": -0.25,
    "CERT_TAMPERED": -0.40,
    "ANOMALY_DETECTED": -0.15,
}

TRUST_DECAY_RATE_PER_HOUR = 0.02  # 2% per hour inactive


@dataclass
class TrustPairRecord:
    """Trust state for a directed pair (agent_id → peer_id)."""
    agent_id: str
    peer_id: str
    trust_score: float = 0.5
    last_interaction: float = field(default_factory=time.time)
    total_messages: int = 0
    violations: int = 0


class DirectedTrustStore:
    """Per-pair trust with hourly decay."""

    def __init__(self) -> None:
        self._pairs: dict[str, TrustPairRecord] = {}  # key = f"{a}->{b}"

    def _key(self, agent_id: str, peer_id: str) -> str:
        return f"{agent_id}->{peer_id}"

    def get_record(self, agent_id: str, peer_id: str) -> TrustPairRecord:
        k = self._key(agent_id, peer_id)
        if k not in self._pairs:
            self._pairs[k] = TrustPairRecord(agent_id=agent_id, peer_id=peer_id)
        return self._pairs[k]

    def get_effective_trust(self, agent_id: str, peer_id: str) -> float:
        rec = self.get_record(agent_id, peer_id)
        hours_inactive = (time.time() - rec.last_interaction) / 3600.0
        decayed = rec.trust_score * ((1 - TRUST_DECAY_RATE_PER_HOUR) ** hours_inactive)
        return max(0.0, min(1.0, decayed))

    def update_trust(
        self, agent_id: str, peer_id: str, event_type: str
    ) -> float:
        rec = self.get_record(agent_id, peer_id)

        # Step 1: Apply time-based decay
        hours_inactive = (time.time() - rec.last_interaction) / 3600.0
        decayed = rec.trust_score * ((1 - TRUST_DECAY_RATE_PER_HOUR) ** hours_inactive)

        # Step 2: Apply event delta
        delta = TRUST_DELTAS.get(event_type, 0.0)
        new_score = max(0.0, min(1.0, decayed + delta))

        rec.trust_score = new_score
        rec.last_interaction = time.time()
        rec.total_messages += 1
        if delta < 0:
            rec.violations += 1

        return new_score

    def get_trust_tier(self, agent_id: str, peer_id: str) -> str:
        """Return the trust-gated tier for policy decisions."""
        score = self.get_effective_trust(agent_id, peer_id)
        if score >= 0.7:
            return "ALLOW"
        elif score >= 0.4:
            return "ALLOW_ENHANCED_LOGGING"
        elif score >= 0.2:
            return "REQUIRE_REVERIFICATION"
        else:
            return "BLOCK"


# =============================================================================
# T4 — SCOPE BINDING
# =============================================================================

@dataclass
class ScopeManifest:
    agent_id: str
    global_scope: list[str] = field(default_factory=list)    # Allowed actions
    forbidden_always: list[str] = field(default_factory=list)  # Never allowed


class ScopeRegistry:
    """Validates proposed actions against agent scope manifests."""

    def __init__(self) -> None:
        self._manifests: dict[str, ScopeManifest] = {}

    def register(self, agent_id: str, scope: list[str], forbidden: list[str] | None = None) -> None:
        self._manifests[agent_id] = ScopeManifest(
            agent_id=agent_id,
            global_scope=scope,
            forbidden_always=forbidden or [],
        )

    def check_scope(self, agent_id: str, action: str) -> VerifyResult | None:
        """Return None if allowed, VerifyResult if blocked."""
        manifest = self._manifests.get(agent_id)
        if manifest is None:
            return None  # No manifest = unrestricted (for backward compat)

        # Check forbidden first
        for forbidden in manifest.forbidden_always:
            if action == forbidden:
                return VerifyResult.FORBIDDEN_ACTION
            if forbidden.endswith("*") and action.startswith(forbidden[:-1]):
                return VerifyResult.FORBIDDEN_ACTION

        # Check global scope
        if not manifest.global_scope:
            return None  # Empty scope = unrestricted

        for scope_item in manifest.global_scope:
            if action == scope_item:
                return None
            if scope_item.endswith("*") and action.startswith(scope_item[:-1]):
                return None
            if scope_item == "*":
                return None

        return VerifyResult.SCOPE_VIOLATION

    def get_manifest(self, agent_id: str) -> ScopeManifest | None:
        return self._manifests.get(agent_id)


# =============================================================================
# T5 — BEHAVIORAL BASELINE (COMPROMISED AGENT DETECTION)
# =============================================================================

ANOMALY_WARN_THRESHOLD = 0.7
ANOMALY_BLOCK_THRESHOLD = 0.9
BASELINE_WINDOW = 20


def _categorize_action(action: str) -> str:
    """Categorize an action string into a behavioral bucket."""
    action_lower = action.lower()
    if any(kw in action_lower for kw in ("file_read", "knowledge", "db_query", "read", "search", "fetch")):
        return "read"
    if any(kw in action_lower for kw in ("file_write", "file_delete", "write", "delete", "update")):
        return "write"
    if any(kw in action_lower for kw in ("web_search", "web_fetch", "api_call", "http", "network")):
        return "network"
    return "system"


class BehavioralBaseline:
    """Rolling window baseline for per-peer action pattern tracking."""

    def __init__(self) -> None:
        self._history: dict[str, deque[str]] = {}  # peer_id → recent categories

    def record(self, peer_id: str, action: str) -> None:
        cat = _categorize_action(action)
        if peer_id not in self._history:
            self._history[peer_id] = deque(maxlen=BASELINE_WINDOW)
        self._history[peer_id].append(cat)

    def anomaly_score(self, peer_id: str, proposed_action: str) -> float:
        """Return 0.0 (normal) to 1.0 (fully anomalous)."""
        history = self._history.get(peer_id)
        if history is None or len(history) < 5:
            return 0.0  # Not enough baseline

        proposed_cat = _categorize_action(proposed_action)
        count = sum(1 for cat in history if cat == proposed_cat)
        return 1.0 - (count / len(history))


# =============================================================================
# UNIFIED L7 LAYER
# =============================================================================

@dataclass
class L7Event:
    """Security event emitted by the L7 layer."""
    layer: str = "L7_InterAgent"
    verdict: str = "allow"
    threat_level: str = "none"
    message: str = ""
    component: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class L7InterAgentLayer:
    """Hardened L7 Inter-Agent Communication Security Layer.

    Processes every inter-agent message through 5 enforcement components:
      1. Replay Prevention (nonce + timestamp)
      2. HMAC Authentication
      3. Delegation Certificate Verification
      4. Trust-Gated Access
      5. Scope Binding + Behavioral Anomaly Detection
    """

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.trust_store = DirectedTrustStore()
        self.scope_registry = ScopeRegistry()
        self.behavioral_baseline = BehavioralBaseline()
        self._shared_secrets: dict[str, str] = {}  # peer_id → shared secret

    def register_peer(
        self,
        peer_id: str,
        shared_secret: str | None = None,
        scope: list[str] | None = None,
        forbidden: list[str] | None = None,
    ) -> str:
        """Register a peer agent and return the shared secret."""
        secret = shared_secret or secrets.token_hex(32)
        self._shared_secrets[peer_id] = secret
        if scope is not None:
            self.scope_registry.register(peer_id, scope, forbidden)
        return secret

    def create_message(
        self,
        receiver_id: str,
        action: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a signed message to send to a peer."""
        secret = self._shared_secrets.get(receiver_id)
        if not secret:
            raise ValueError(f"Peer '{receiver_id}' not registered")
        return create_signed_payload(
            sender_id=self.agent_id,
            receiver_id=receiver_id,
            action=action,
            body=body,
            shared_secret=secret,
        )

    def verify_incoming(
        self,
        payload: dict[str, Any],
        delegation_cert: DelegationCertificate | None = None,
    ) -> tuple[VerifyResult, L7Event]:
        """Full L7 verification pipeline on an incoming inter-agent message."""
        sender_id = payload.get("sender_id", "unknown")
        action = payload.get("action", "")

        # --- T1: Replay Prevention ---
        secret = self._shared_secrets.get(sender_id)
        if not secret:
            evt = L7Event(
                verdict="block", threat_level="high",
                message=f"Unknown sender '{sender_id}' — not registered",
                component="replay_prevention",
            )
            return VerifyResult.TAMPERED, evt

        result = verify_message(payload, secret)
        if result == VerifyResult.REPLAY_EXPIRED:
            self.trust_store.update_trust(sender_id, self.agent_id, "REPLAY_DETECTED")
            evt = L7Event(
                verdict="block", threat_level="high",
                message=f"Message timestamp expired (>{MAX_CLOCK_SKEW}s skew)",
                component="replay_prevention",
            )
            return result, evt

        if result == VerifyResult.REPLAY_DETECTED:
            self.trust_store.update_trust(sender_id, self.agent_id, "REPLAY_DETECTED")
            evt = L7Event(
                verdict="block", threat_level="critical",
                message="Replay attack detected — same nonce reused",
                component="replay_prevention",
            )
            return result, evt

        if result == VerifyResult.TAMPERED:
            self.trust_store.update_trust(sender_id, self.agent_id, "HMAC_FAILURE")
            evt = L7Event(
                verdict="block", threat_level="critical",
                message="HMAC verification failed — message tampered",
                component="replay_prevention",
            )
            return result, evt

        # --- T3: Trust-Gated Access ---
        tier = self.trust_store.get_trust_tier(sender_id, self.agent_id)
        if tier == "BLOCK":
            score = self.trust_store.get_effective_trust(sender_id, self.agent_id)
            evt = L7Event(
                verdict="block", threat_level="critical",
                message=f"Agent '{sender_id}' trust too low: {score:.3f}",
                component="trust_gate",
                details={"trust_score": score, "label": "low_trust_agent_blocked"},
            )
            return VerifyResult.BLOCKED_LOW_TRUST, evt

        # --- T2: Delegation Certificate ---
        if delegation_cert is not None:
            cert_result = verify_delegated_action(action, delegation_cert, secret)
            if cert_result != VerifyResult.ALLOW:
                event_type = {
                    VerifyResult.DELEGATION_EXPIRED: "CERT_TAMPERED",
                    VerifyResult.DELEGATION_DEPTH_EXCEEDED: "SCOPE_VIOLATION",
                    VerifyResult.SCOPE_VIOLATION: "SCOPE_VIOLATION",
                    VerifyResult.CERTIFICATE_TAMPERED: "CERT_TAMPERED",
                }.get(cert_result, "SCOPE_VIOLATION")
                self.trust_store.update_trust(sender_id, self.agent_id, event_type)
                evt = L7Event(
                    verdict="block", threat_level="high",
                    message=f"Delegation check failed: {cert_result.value}",
                    component="delegation_chain",
                    details={"certificate_id": delegation_cert.certificate_id},
                )
                return cert_result, evt
            # Cert passed → credit
            self.trust_store.update_trust(sender_id, self.agent_id, "SCOPE_HONORED")

        # --- T4: Scope Binding ---
        scope_result = self.scope_registry.check_scope(sender_id, action)
        if scope_result is not None:
            self.trust_store.update_trust(sender_id, self.agent_id, "SCOPE_VIOLATION")
            label = "forbidden_action" if scope_result == VerifyResult.FORBIDDEN_ACTION else "global_scope_violation"
            evt = L7Event(
                verdict="block", threat_level="high",
                message=f"Scope binding violation: {label} for action '{action}'",
                component="scope_binding",
                details={"action": action, "label": label},
            )
            return scope_result, evt

        # --- T5: Behavioral Anomaly ---
        anomaly = self.behavioral_baseline.anomaly_score(sender_id, action)
        if anomaly > ANOMALY_BLOCK_THRESHOLD:
            self.trust_store.update_trust(sender_id, self.agent_id, "ANOMALY_DETECTED")
            evt = L7Event(
                verdict="block", threat_level="critical",
                message=f"Behavioral anomaly BLOCKED: score={anomaly:.2f} for action '{action}'",
                component="behavioral_baseline",
                details={"anomaly_score": anomaly, "label": "suspected_compromised_agent"},
            )
            return VerifyResult.ANOMALY_BLOCKED, evt

        anomaly_event = None
        if anomaly > ANOMALY_WARN_THRESHOLD:
            anomaly_event = {
                "anomaly_score": anomaly,
                "label": "behavioral_anomaly_detected",
                "severity": "high",
            }

        # Record action in baseline
        self.behavioral_baseline.record(sender_id, action)

        # All passed
        self.trust_store.update_trust(sender_id, self.agent_id, "MESSAGE_VERIFIED")
        trust_score = self.trust_store.get_effective_trust(sender_id, self.agent_id)

        details: dict[str, Any] = {"trust_score": trust_score}
        if tier == "ALLOW_ENHANCED_LOGGING":
            details["enhanced_logging"] = True
        if tier == "REQUIRE_REVERIFICATION":
            details["requires_reverification"] = True
        if anomaly_event:
            details["anomaly"] = anomaly_event

        evt = L7Event(
            verdict="allow",
            threat_level="none" if not anomaly_event else "medium",
            message="Inter-agent message verified",
            component="pipeline",
            details=details,
        )
        return VerifyResult.ALLOW, evt
