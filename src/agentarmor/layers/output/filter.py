"""Layer 6: Output Response Security — PII redaction, DLP, sensitivity filtering."""

from __future__ import annotations

import re
from typing import Any

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import OutputConfig
from agentarmor.core.types import (
    AgentEvent,
    LayerResult,
    SecurityVerdict,
    ThreatLevel,
)


class PIIRedactor:
    """Detects and redacts PII from agent outputs using Microsoft Presidio."""

    def __init__(self, entities: list[str] | None = None, language: str = "en"):
        self._entities = entities or [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
            "US_SSN", "IBAN_CODE", "IP_ADDRESS", "CRYPTO",
        ]
        self._language = language
        self._analyzer = None
        self._anonymizer = None
        self._initialized = False

    def _init_engines(self) -> None:
        if self._initialized:
            return
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
            self._analyzer = AnalyzerEngine()
            self._anonymizer = AnonymizerEngine()
            self._initialized = True
        except ImportError:
            self._initialized = True

    def analyze(self, text: str) -> list[dict[str, Any]]:
        self._init_engines()
        if not self._analyzer:
            return []
        results = self._analyzer.analyze(text=text, entities=self._entities, language=self._language)
        return [
            {"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score, "text": text[r.start:r.end]}
            for r in results
        ]

    def redact(self, text: str) -> tuple[str, list[dict[str, Any]]]:
        self._init_engines()
        if not self._analyzer or not self._anonymizer:
            return text, []
        results = self._analyzer.analyze(text=text, entities=self._entities, language=self._language)
        if not results:
            return text, []
        anonymized = self._anonymizer.anonymize(text=text, analyzer_results=results)
        found = [{"entity_type": r.entity_type, "score": r.score} for r in results]
        return anonymized.text, found


class FallbackPIIRedactor:
    """Regex-based PII redaction fallback when Presidio is not available."""

    PATTERNS: dict[str, re.Pattern[str]] = {
        "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "PHONE": re.compile(r"(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
        "IP_ADDRESS": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "API_KEY": re.compile(r"(?:sk|pk|api|key|token)[-_][a-zA-Z0-9]{20,}"),
    }

    @classmethod
    def redact(cls, text: str) -> tuple[str, list[dict[str, str]]]:
        found = []
        result = text
        for entity_type, pattern in cls.PATTERNS.items():
            matches = pattern.findall(result)
            for match in matches:
                found.append({"entity_type": entity_type, "text": match[:10] + "..."})
                result = result.replace(match, f"<{entity_type}>")
        return result, found


class SensitivityFilter:
    def __init__(self, blocked_keywords: list[str] | None = None):
        self._blocked = [kw.lower() for kw in (blocked_keywords or [])]

    def check(self, text: str) -> list[str]:
        text_lower = text.lower()
        return [kw for kw in self._blocked if kw in text_lower]


class OutputLayer(SecurityLayer):
    """Layer 6: Scans and filters agent output for PII, sensitive data, and policy violations."""

    name = "L6_output"

    def __init__(self, config: OutputConfig | None = None):
        self.config = config or OutputConfig()
        self.pii_redactor = PIIRedactor(entities=self.config.pii_entities)
        self.fallback_redactor = FallbackPIIRedactor()
        self.sensitivity_filter = SensitivityFilter(blocked_keywords=self.config.blocked_keywords)

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")

        output_text = self._extract_output_text(event)
        if not output_text:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="No output to scan")

        findings: list[dict[str, Any]] = []
        modified_text = output_text

        if self.config.pii_redaction:
            try:
                modified_text, pii_found = self.pii_redactor.redact(output_text)
            except Exception:
                modified_text, pii_found = self.fallback_redactor.redact(output_text)
            if pii_found:
                findings.append({"type": "pii_detected", "entities": pii_found, "count": len(pii_found)})

        if self.config.sensitivity_filtering:
            blocked = self.sensitivity_filter.check(output_text)
            if blocked:
                findings.append({"type": "blocked_keywords", "keywords": blocked})

        if findings:
            has_blocked = any(f["type"] == "blocked_keywords" for f in findings)
            has_pii = any(f["type"] == "pii_detected" for f in findings)
            if has_blocked:
                return LayerResult(
                    layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.HIGH,
                    message="Output contains blocked content", details={"findings": findings},
                )
            if has_pii:
                return LayerResult(
                    layer=self.name, verdict=SecurityVerdict.MODIFY, threat_level=ThreatLevel.MEDIUM,
                    message="PII redacted from output", modified_data=modified_text,
                    details={"findings": findings},
                )

        return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Output clean")

    def _extract_output_text(self, event: AgentEvent) -> str:
        if isinstance(event.output_data, str):
            return event.output_data
        if isinstance(event.output_data, dict):
            return str(event.output_data)
        return ""
