"""Layer 1: Data Ingestion Security — input scanning, injection detection, source verification."""
from __future__ import annotations

import re
import unicodedata
from typing import Any

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import IngestionConfig
from agentarmor.core.types import AgentEvent, LayerResult, SecurityVerdict, ThreatLevel

# --- Constants for D1: Unicode Normalization & Content Disarm ---
ZERO_WIDTH_CHARS = {
    '\u200b', '\u200c', '\u200d', '\u200e', '\u200f', '\u202a', '\u202b',
    '\u202c', '\u202d', '\u202e', '\u2060', '\u2061', '\u2062', '\u2063',
    '\u2064', '\ufeff', '\u00ad',
}

HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o',
    'р': 'r', 'с': 'c', 'х': 'x', 'р': 'p',
    'ο': 'o', 'α': 'a', 'ε': 'e',
}

ENCODING_PATTERNS = [
    (re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'), 'base64_candidate'),
    (re.compile(r'(?:%[0-9A-Fa-f]{2}){5,}'),  'url_encoded'),
    (re.compile(r'&#[0-9]{2,5};'),            'html_entity'),
]

# --- Constants for D2: Syntactic Pattern Matching ---
L1_PATTERNS = {
    "role_override_explicit": [
        re.compile(r"(?i)(ignore|disregard|forget|override|bypass|skip)\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|constraints?|guidelines?|directives?|system)"),
        re.compile(r"(?i)(you are|act as|pretend to be|roleplay as|simulate being)\s+(an?\s+)?(unfiltered|unrestricted|uncensored|jailbroken|free|evil|malicious)"),
        re.compile(r"(?i)do not\s+(follow|apply|use|obey)\s+(your|the|any)\s+(rules?|safety|guidelines?|instructions?)"),
        re.compile(r"(?i)(new|updated|revised|actual|real|true)\s+(system\s+)?(prompt|instructions?|directives?|role)\s*:"),
        re.compile(r"(?i)your\s+(true|real|actual|original)\s+(purpose|goal|mission|function|instructions?)\s+is"),
    ],
    "delimiter_injection": [
        re.compile(r"(?i)[-=_*]{5,}\s*(end\s+of\s+)?(system\s+)?(prompt|instructions?|context|rules?)\s*[-=_*]{5,}"),
        re.compile(r"(?i)</?(?:system|user|assistant|human|ai|inst|s|\/s)>"),
        re.compile(r"\[INST\]|\[\/INST\]"),
        re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|<\|eot_id\|>"),
        re.compile(r"(?i)###\s*(system|instruction|override|new\s+prompt|admin)"),
        re.compile(r"(?i)\n{3,}(you are|your role|your purpose|ignore|disregard)"),
    ],
    "exfiltration": [
        re.compile(r"(?i)(print|output|show|reveal|display|share|leak|dump|return|repeat|echo|copy|quote)\s+(your|the)?\s*(system\s+)?(prompt|instructions?|config|api\s+key|secret|token|password|credentials?)"),
        re.compile(r"(?i)what\s+(are|is)\s+(your|the)\s*(system\s+)?(prompt|instructions?|configuration|rules?)"),
        re.compile(r"(?i)(exfiltrat|steal|extract|harvest)\s+(data|information|credentials?|keys?|tokens?)"),
        re.compile(r"(?i)send\s+.{0,50}(to\s+)?(http[s]?://|webhook|external|remote)"),
        re.compile(r"(?i)(encode|convert)\s+.{0,30}(and\s+)?(send|post|upload|exfiltrate)"),
    ],
    "jailbreak": [
        re.compile(r"(?i)\sDAN\s"),
        re.compile(r"(?i)jailbreak"),
        re.compile(r"(?i)(developer|maintenance|admin|debug|god|unrestricted)\s+mode"),
        re.compile(r"(?i)as\s+(a|an)\s+(evil|malicious|unrestricted|unaligned|uncensored)\s+(AI|assistant|model|LLM|bot|GPT)"),
        re.compile(r"(?i)hypothetically\s+(speaking|if|assume).{0,80}(no\s+restrictions?|unlimited|unconstrained|no\s+rules?)"),
        re.compile(r"(?i)(imagine|suppose|pretend|assume)\s+(there\s+(are|is)\s+no|you\s+have\s+no)\s+(rules?|restrictions?|guidelines?|safety|filters?)"),
        re.compile(r"(?i)(for\s+)?(educational|research|fiction|creative|academic|hypothetical)\s+(purposes?).{0,40}(how\s+to|explain\s+how|steps\s+to)\s+(hack|exploit|bypass|attack|harm|destroy|steal)"),
    ],
    "indirect_extraction": [
        re.compile(r"(?i)translate\s+your\s+(system\s+)?prompt\s+to"),
        re.compile(r"(?i)(summarize|paraphrase|rewrite|rephrase)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)"),
        re.compile(r"(?i)what\s+(would|did|does)\s+your\s+(creator|developer|maker|openai|anthropic|mistral|meta)\s+(say|tell|instruct|define)"),
        re.compile(r"(?i)complete\s+(this|the\s+following)\s+(sentence|text|prompt)\s*:?\s*[\"']?(you\s+are|your\s+purpose|your\s+instructions?|you\s+must)"),
        re.compile(r"(?i)(tell|show)\s+me\s+(what\s+)?(you\s+(were|are)\s+told|your\s+(secret|hidden|real)\s+(instructions?|prompt))"),
    ],
    "tool_manipulation": [
        re.compile(r"(?i)bypass\s+(the\s+)?(tool|security|safety|layer\s+[1-8]|filter|guard|agentarmor)"),
        re.compile(r"(?i)(directly\s+)?(access|read|write|modify|delete)\s+(the\s+)?(system|root|admin|internal|host)\s+(files?|database|config|network)"),
        re.compile(r"(?i)(execute|run|call)\s+(arbitrary|any|all)\s+(code|command|tool|function|script)"),
        re.compile(r"(?i)disable\s+(layer|L[1-8]|security|safety|protection|guard)"),
    ],
    "obfuscation": [
        re.compile(r"(?i)(decode\s+this|this\s+is\s+(base64|rot13|hex)\s+encoded?)\s*:?"),
        re.compile(r"[A-Za-z0-9+/]{30,}={0,2}"),
        re.compile(r"(?i)(encoded?\s+message|hidden\s+instruction)\s*:"),
    ],
}

CATEGORY_SEVERITY = {
    "role_override_explicit": 9,
    "delimiter_injection": 8,
    "exfiltration": 9,
    "jailbreak": 8,
    "indirect_extraction": 7,
    "tool_manipulation": 8,
    "obfuscation": 6,
}

# --- Initialization of D3 (Llama Prompt Guard 2) and D4 (GPT-2 Perplexity) ---
try:
    from transformers import pipeline as hf_pipeline
    _pg_classifier = hf_pipeline(
        "text-classification",
        model="meta-llama/Llama-Prompt-Guard-2-22M",
        device=-1,
        truncation=True,
        max_length=512,
    )
    PROMPT_GUARD_AVAILABLE = True
except Exception as e:
    print(f"AgentArmor L1 (D3) skipped: {e}")
    PROMPT_GUARD_AVAILABLE = False


try:
    import torch
    from transformers import GPT2LMHeadModel, GPT2TokenizerFast

    _gpt2_model = GPT2LMHeadModel.from_pretrained("gpt2")
    _gpt2_tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
    _gpt2_model.eval()
    PERPLEXITY_AVAILABLE = True
except Exception as e:
    print(f"AgentArmor L1 (D4) skipped: {e}")
    PERPLEXITY_AVAILABLE = False


def normalize_and_disarm(text: str) -> tuple[str, list[str]]:
    """D1 protection step: Unicode normalization and content disarm."""
    anomalies = []

    # 1. Detect and strip zero-width chars
    zw_found = [c for c in text if c in ZERO_WIDTH_CHARS]
    if zw_found:
        anomalies.append(f"zero_width_chars:{len(zw_found)}_instances")
        text = ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)

    # 2. Detect RTL override (bidi attack)
    if '\u202e' in text or '\u202d' in text:
        anomalies.append("bidi_override_detected")
        text = text.replace('\u202e', '').replace('\u202d', '')

    # 3. Normalize homoglyphs
    normalized = []
    homoglyphs_found = 0
    for char in text:
        if char in HOMOGLYPH_MAP:
            normalized.append(HOMOGLYPH_MAP[char])
            homoglyphs_found += 1
        else:
            normalized.append(char)
    if homoglyphs_found > 2:
        anomalies.append(f"homoglyphs:{homoglyphs_found}_substitutions")
    text = ''.join(normalized)

    # 4. NFKC normalization
    text = unicodedata.normalize('NFKC', text)

    # 5. Detect encoding obfuscation
    for pattern, label in ENCODING_PATTERNS:
        if pattern.search(text):
            anomalies.append(f"encoding_obfuscation:{label}")

    return text, anomalies


def classify_with_prompt_guard(text: str) -> tuple[str, float]:
    """D3 protection step: Semantic analysis using Llama Prompt Guard 2."""
    if not PROMPT_GUARD_AVAILABLE:
        return ("UNKNOWN", 0.0)
    result = _pg_classifier(text[:512])[0]
    return result["label"], result["score"]


def compute_perplexity(text: str) -> float:
    """D4 protection step: Detect GPT-2 perplexity for GCG suffixes."""
    if not PERPLEXITY_AVAILABLE or len(text) < 20:
        return 0.0
    inputs = _gpt2_tokenizer(text[:200], return_tensors="pt", truncation=True)
    with torch.no_grad():
        outputs = _gpt2_model(**inputs, labels=inputs["input_ids"])
    return torch.exp(outputs.loss).item()


class IngestionLayer(SecurityLayer):
    name = "L1_ingestion"

    def __init__(self, config: IngestionConfig | None = None):
        self.config = config or IngestionConfig()

    async def process(self, event: AgentEvent) -> LayerResult:
        import time
        start_time = time.time()
        
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")

        input_text = self._extract_text(event)
        source_context = event.metadata.get("source", "user_input")

        # Details struct for reporting
        details = {
            "vector": source_context,
            "source": event.metadata.get("agent_id", "user"),
            "defenses_applied": [],
            "anomalies_found": [],
            "processing_ms": 0.0,
            "regex_categories_matched": [],
        }

        # --- D1 Normalized Content ---
        normalized, d1_anomalies = normalize_and_disarm(input_text)
        details["defenses_applied"].append("D1")
        if d1_anomalies:
            details["unicode_anomalies"] = len(d1_anomalies)
            for anomaly in d1_anomalies:
                details["anomalies_found"].append({"type": anomaly, "severity": 2})

        threat_score = 0
        if d1_anomalies:
            threat_score += 2
        
        # --- D2 Synactic Patterns ---
        d2_hits = []
        for category, patterns in L1_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(normalized)
                if match:
                    d2_hits.append(category)
                    sev = CATEGORY_SEVERITY[category]
                    details["regex_categories_matched"].append(category)
                    details["anomalies_found"].append({
                        "type": "regex_match",
                        "category": category,
                        "severity": sev,
                        "matched_text": match.group()[:100]
                    })
                    threat_score = max(threat_score, sev)
                    break # one hit per category is enough
        details["defenses_applied"].append("D2")

        # --- D3 Semantic Classification ---
        details["defenses_applied"].append("D3")
        pg_label, pg_score = classify_with_prompt_guard(normalized)
        details["classifier_label"] = pg_label
        details["classifier_confidence"] = pg_score
        
        if pg_label in ("INJECTION", "JAILBREAK"):
            if pg_score >= 0.85:
                # Same severity as Category D jailbreak
                details["anomalies_found"].append({
                    "type": "classifier_injection",
                    "category": "jailbreak_semantic",
                    "severity": 8,
                    "confidence": pg_score,
                })
                threat_score = max(threat_score, 8)
            elif pg_score >= 0.70:
                # Just flags it
                details["anomalies_found"].append({
                    "type": "classifier_injection_candidate",
                    "category": "jailbreak_semantic",
                    "severity": 5,
                    "confidence": pg_score,
                })
                threat_score = max(threat_score, 5)

        # --- D4 Perplexity Filtering (User Input Only) ---
        if source_context == "user_input":
            details["defenses_applied"].append("D4")
            ppl = compute_perplexity(normalized)
            details["perplexity_score"] = ppl
            token_count = len(normalized.split())
            if ppl > 1000 and token_count < 200:
                details["anomalies_found"].append({
                    "type": "high_perplexity",
                    "category": "gcg_adversarial_suffix_candidate",
                    "severity": 7,
                    "matched_text": "Perplexity: " + str(ppl)
                })
                # Only block if other trigger exists, otherwise just heavily flag
                if d2_hits or pg_label in ["INJECTION", "JAILBREAK"]:
                    threat_score = max(threat_score, 8)
                else:
                    threat_score = max(threat_score, 7)
        else:
            details["perplexity_score"] = None

        # --- Verdict Resolution ---
        threat_level = ThreatLevel.NONE
        verdict = SecurityVerdict.ALLOW

        if threat_score >= 9:
            threat_level = ThreatLevel.CRITICAL
            verdict = SecurityVerdict.DENY
            msg = "Critical injection patterns detected. Request blocked."
        elif threat_score >= 7:
            threat_level = ThreatLevel.HIGH
            verdict = SecurityVerdict.DENY
            msg = "High threat injection patterns detected. Request blocked."
        elif threat_score >= 5:
            threat_level = ThreatLevel.MEDIUM
            verdict = SecurityVerdict.AUDIT
            msg = "Moderate injection anomalies detected. Request flagged."
        elif threat_score >= 2:
            threat_level = ThreatLevel.LOW
            verdict = SecurityVerdict.ALLOW
            msg = "Minor anomalies detected. Request allowed."
        else:
            msg = "Input cleanly passed all L1 checks."
            
        details["processing_ms"] = round((time.time() - start_time) * 1000, 2)

        return LayerResult(
            layer=self.name,
            verdict=verdict,
            threat_level=threat_level,
            message=msg,
            details=details
        )

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
