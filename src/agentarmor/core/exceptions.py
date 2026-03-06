"""Exception hierarchy for AgentArmor."""


class AgentArmorError(Exception):
    pass


class PolicyViolationError(AgentArmorError):
    def __init__(self, layer: str, action: str, reason: str):
        self.layer = layer
        self.action = action
        self.reason = reason
        super().__init__(f"[{layer}] Policy violation on '{action}': {reason}")


class EncryptionError(AgentArmorError):
    pass


class AuthenticationError(AgentArmorError):
    pass


class RateLimitError(AgentArmorError):
    def __init__(self, action: str, limit: int, window_seconds: int):
        self.action = action
        self.limit = limit
        super().__init__(f"Rate limit exceeded for '{action}': max {limit} per {window_seconds}s")


class InjectionDetectedError(AgentArmorError):
    pass


class DataClassificationError(AgentArmorError):
    pass


class SandboxViolationError(AgentArmorError):
    pass


class TrustScoreError(AgentArmorError):
    pass
