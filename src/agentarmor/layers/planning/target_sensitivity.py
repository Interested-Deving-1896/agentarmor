"""Target-sensitive risk scoring for L4 planning layer.

Adjusts verb-based risk scores by considering the sensitivity of the
target resource (file path, URL, etc.) referenced in action parameters.
"""
from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

# Ordered list of (glob_pattern, multiplier).  Checked top-to-bottom;
# the *highest* matching multiplier wins (not first-match).
TARGET_SENSITIVITY_MAP: list[tuple[str, float]] = [
    # Critical system config
    ("/etc/shadow", 4.0),
    ("/etc/passwd", 4.0),
    ("/etc/*", 4.0),
    # User secret material
    ("~/.ssh/*", 4.0),
    ("~/.aws/*", 4.0),
    ("~/.gnupg/*", 4.0),
    # Privileged system directories
    ("/root/*", 3.5),
    ("/sys/*", 3.5),
    ("/proc/*", 3.5),
    # Audit / log files
    ("/var/log/*", 2.0),
    # Low-sensitivity temp directories
    ("/tmp/*", 0.5),
    ("/var/tmp/*", 0.5),
]

DEFAULT_MULTIPLIER: float = 1.0

# Keys checked (in order) when extracting a target from action params.
_TARGET_KEYS: list[str] = ["path", "file", "target", "resource", "url", "key"]


def get_target_multiplier(params: dict[str, Any]) -> float:
    """Return the highest sensitivity multiplier matching any target in *params*.

    Checks common parameter keys (path, file, target, resource, url, key)
    and matches their values against ``TARGET_SENSITIVITY_MAP`` glob patterns.
    Returns ``DEFAULT_MULTIPLIER`` (1.0) when nothing matches.
    """
    target: str | None = None
    for key in _TARGET_KEYS:
        if key in params and isinstance(params[key], str) and params[key]:
            target = params[key]
            break

    if target is None:
        return DEFAULT_MULTIPLIER

    best: float | None = None
    for pattern, multiplier in TARGET_SENSITIVITY_MAP:
        if fnmatch(target, pattern) and (best is None or multiplier > best):
            best = multiplier
    return best if best is not None else DEFAULT_MULTIPLIER


def compute_composite_score(verb_score: int, params: dict[str, Any]) -> float:
    """Compute a composite risk score combining verb risk and target sensitivity.

    Returns ``min(10.0, verb_score * get_target_multiplier(params))``.
    """
    return min(10.0, verb_score * get_target_multiplier(params))
