"""Layer 1: Data Ingestion Security — input scanning, injection detection, source verification."""
from __future__ import annotations

import re
from typing import Any

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import IngestionConfig
from agentarmor.core.types import AgentEvent, LayerResult, SecurityVerdict, ThreatLevel

INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules)", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|above|prior)", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
    re.compile(r"new\s+instructions?:\s*", re.I),
    re.compile(r"system\s*prompt\s*:", re.I),
    re.compile(r"\[SYSTEM\]", re.I),
    re.compile(r"<\s*system\s*>", re.I),
    re.compile(r"forget\s+(everything|all|your)\s+(you|instructions|rules)", re.I),
    re.compile(r"override\s+(safety|security|instructions|rules)", re.I),
    re.compile(r"act\s+as\s+(if|though)\s+you\s+(have\s+no|don.t\s+have)", re.I),
    re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"DAN\s*mode", re.I),
    re.compile(r"do\s+anything\s+now", re.I),
    re.compile(r"(print|show|display|output|reveal|repeat|give\s+me)\s+(me\s+)?(your|the\s+system)\s+(system\s+)?(prompt|instructions|rules)", re.I),
    re.compile(r"what\s+(are|were)\s+your\s+(initial|original|system\s+)?(instructions|prompt|rules)", re.I),
    re.compile(r"what\s+(are|were)\s+the\s+(initial|original|system)\s+(instructions|prompt|rules)", re.I),
    re.compile(r"your\s+(system|initial|original)\s+(prompt|instructions|rules)", re.I),
    re.compile(r"the\s+system\s+prompt", re.I),
    re.compile(r"(tell\s+me|show\s+me|give\s+me)\s+your\s+(prompt|instructions|rules)", re.I),
    re.compile(r"repeat\s+(the\s+)?(text|words|instructions)\s+above", re.I),
    re.compile(r"send\s+(this|the|all)\s+(data|info|information)\s+to", re.I),
    re.compile(r"(curl|wget|fetch|http)\s+https?://", re.I),
    re.compile(r"base64\s*encode", re.I),
    re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]"),
]

OBFUSCATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"&#x?[0-9a-fA-F]+;"),
    re.compile(r"\\u[0-9a-fA-F]{4}"),
    re.compile(r"\\x[0-9a-fA-F]{2}"),
    re.compile(r"%[0-9a-fA-F]{2}"),
]


class IngestionLayer(SecurityLayer):
    name = "L1_ingestion"

    def __init__(self, config: IngestionConfig | None = None):
        self.config = config or IngestionConfig()
        self._custom_patterns: list[re.Pattern[str]] = []
        if self.config.blocked_patterns:
            for p in self.config.blocked_patterns:
                self._custom_patterns.append(re.compile(p, re.I))

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")
        findings: list[dict[str, Any]] = []
        threat = ThreatLevel.NONE
        input_text = self._extract_text(event)

        if len(input_text.encode("utf-8")) > self.config.max_input_size_bytes:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.MEDIUM,
                message=f"Input exceeds maximum size ({self.config.max_input_size_bytes} bytes)")

        source = event.metadata.get("source", "")
        if self.config.allowed_sources and source:
            if not any(s in source for s in self.config.allowed_sources):
                findings.append({"type": "unauthorized_source", "source": source})
                threat = ThreatLevel.HIGH

        if self.config.scan_for_injection:
            injection_hits = self._detect_injection(input_text)
            if injection_hits:
                findings.extend(injection_hits)
                threat = ThreatLevel.HIGH

        obfuscation_hits = self._detect_obfuscation(input_text)
        if obfuscation_hits:
            findings.extend(obfuscation_hits)
            if threat == ThreatLevel.NONE:
                threat = ThreatLevel.MEDIUM

        for pattern in self._custom_patterns:
            match = pattern.search(input_text)
            if match:
                findings.append({"type": "blocked_pattern", "pattern": pattern.pattern, "match": match.group()[:100]})
                threat = ThreatLevel.HIGH

        if findings:
            verdict = SecurityVerdict.DENY if threat in (ThreatLevel.HIGH, ThreatLevel.CRITICAL) else SecurityVerdict.AUDIT
            return LayerResult(layer=self.name, verdict=verdict, threat_level=threat,
                message=f"Detected {len(findings)} issue(s) in input data", details={"findings": findings})
        return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Input clean")

    def _extract_text(self, event: AgentEvent) -> str:
        parts: list[str] = []
        if isinstance(event.input_data, str):
            parts.append(event.input_data)
        elif isinstance(event.input_data, dict):
            parts.extend(str(v) for v in event.input_data.values())
        elif isinstance(event.input_data, list):
            for item in event.input_data:
                if isinstance(item, dict):
                    content = item.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                elif isinstance(item, str):
                    parts.append(item)
        for v in event.params.values():
            if isinstance(v, str):
                parts.append(v)
        return "\n".join(parts)

    def _detect_injection(self, text: str) -> list[dict[str, Any]]:
        hits = []
        for pattern in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                hits.append({"type": "prompt_injection", "pattern": pattern.pattern[:80], "match": match.group()[:100], "position": match.start()})
        return hits

    def _detect_obfuscation(self, text: str) -> list[dict[str, Any]]:
        hits = []
        for pattern in OBFUSCATION_PATTERNS:
            matches = pattern.findall(text)
            if len(matches) > 3:
                hits.append({"type": "obfuscation", "pattern": pattern.pattern, "count": len(matches)})
        return hits
