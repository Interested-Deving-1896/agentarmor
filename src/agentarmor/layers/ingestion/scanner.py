"""Layer 1: Data Ingestion Security — input scanning, injection detection, source verification."""
from __future__ import annotations

import asyncio
import hashlib
import re
import time
import unicodedata
from pathlib import Path
from typing import Any

import structlog
import yaml

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import IngestionConfig
from agentarmor.core.types import AgentEvent, LayerResult, SecurityVerdict, ThreatLevel

log = structlog.get_logger(__name__)

# --- Constants for D1: Unicode Normalization & Content Disarm ---
ZERO_WIDTH_CHARS = {
    '​', '‌', '‍', '‎', '‏', '‪', '‫',
    '‬', '‭', '‮', '⁠', '⁡', '⁢', '⁣',
    '⁤', '﻿', '­',
}

HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o',
    'р': 'r', 'с': 'c', 'х': 'x',
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
        re.compile(r"(?i)(ignore|disregard|forget|override|bypass|skip)\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|constraints?|guidelines?|directives?|system)"),  # noqa: E501
        re.compile(r"(?i)(you are|act as|pretend to be|roleplay as|simulate being)\s+(an?\s+)?(unfiltered|unrestricted|uncensored|jailbroken|free|evil|malicious)"),  # noqa: E501
        re.compile(r"(?i)do not\s+(follow|apply|use|obey)\s+(your|the|any)\s+(rules?|safety|guidelines?|instructions?)"),  # noqa: E501
        re.compile(r"(?i)(new|updated|revised|actual|real|true)\s+(system\s+)?(prompt|instructions?|directives?|role)\s*:"),  # noqa: E501
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
        re.compile(r"(?i)(print|output|show|reveal|display|share|leak|dump|return|repeat|echo|copy|quote)\s+(your|the)?\s*(system\s+)?(prompt|instructions?|config|api\s+key|secret|token|password|credentials?)"),  # noqa: E501
        re.compile(r"(?i)what\s+(are|is)\s+(your|the)\s*(system\s+)?(prompt|instructions?|configuration|rules?)"),
        re.compile(r"(?i)(exfiltrat|steal|extract|harvest)\s+(data|information|credentials?|keys?|tokens?)"),
        re.compile(r"(?i)send\s+.{0,50}(to\s+)?(http[s]?://|webhook|external|remote)"),
        re.compile(r"(?i)(encode|convert)\s+.{0,30}(and\s+)?(send|post|upload|exfiltrate)"),
    ],
    "jailbreak": [
        re.compile(r"(?i)\sDAN\s"),
        re.compile(r"(?i)jailbreak"),
        re.compile(r"(?i)(developer|maintenance|admin|debug|god|unrestricted)\s+mode"),
        re.compile(r"(?i)as\s+(a|an)\s+(evil|malicious|unrestricted|unaligned|uncensored)\s+(AI|assistant|model|LLM|bot|GPT)"),  # noqa: E501
        re.compile(r"(?i)hypothetically\s+(speaking|if|assume).{0,80}(no\s+restrictions?|unlimited|unconstrained|no\s+rules?)"),  # noqa: E501
        re.compile(r"(?i)(imagine|suppose|pretend|assume)\s+(there\s+(are|is)\s+no|you\s+have\s+no)\s+(rules?|restrictions?|guidelines?|safety|filters?)"),  # noqa: E501
        re.compile(r"(?i)(for\s+)?(educational|research|fiction|creative|academic|hypothetical)\s+(purposes?).{0,40}(how\s+to|explain\s+how|steps\s+to)\s+(hack|exploit|bypass|attack|harm|destroy|steal)"),  # noqa: E501
    ],
    "indirect_extraction": [
        re.compile(r"(?i)translate\s+your\s+(system\s+)?prompt\s+to"),
        re.compile(r"(?i)(summarize|paraphrase|rewrite|rephrase)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)"),  # noqa: E501
        re.compile(r"(?i)what\s+(would|did|does)\s+your\s+(creator|developer|maker|openai|anthropic|mistral|meta)\s+(say|tell|instruct|define)"),  # noqa: E501
        re.compile(r"(?i)complete\s+(this|the\s+following)\s+(sentence|text|prompt)\s*:?\s*[\"']?(you\s+are|your\s+purpose|your\s+instructions?|you\s+must)"),  # noqa: E501
        re.compile(r"(?i)(tell|show)\s+me\s+(what\s+)?(you\s+(were|are)\s+told|your\s+(secret|hidden|real)\s+(instructions?|prompt))"),  # noqa: E501
    ],
    "tool_manipulation": [
        re.compile(r"(?i)bypass\s+(the\s+)?(tool|security|safety|layer\s+[1-8]|filter|guard|agentarmor)"),
        re.compile(r"(?i)(directly\s+)?(access|read|write|modify|delete)\s+(the\s+)?(system|root|admin|internal|host)\s+(files?|database|config|network)"),  # noqa: E501
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

# DeBERTa label mapping: LABEL_1 = injection, LABEL_0 = safe
_DEBERTA_LABEL_MAP = {"LABEL_1": "INJECTION", "LABEL_0": "SAFE"}

# Inference timeout (seconds) for D3/D4/D5 model calls — prevents runaway hangs.
_MODEL_TIMEOUT_S = 5.0

# Corpus + cache locations
_CORPUS_PATH = Path(__file__).resolve().parents[2] / "data" / "jailbreak_corpus.yaml"
_EMBED_CACHE_DIR = Path.home() / ".cache" / "agentarmor" / "embeddings"

# Lazy-load state for each detector. Loaded on first call, never at import time.
_d3_state: dict[str, Any] = {"loaded": False, "available": False, "pipeline": None}
_d4_state: dict[str, Any] = {"loaded": False, "available": False, "model": None, "tokenizer": None}
_d5_state: dict[str, Any] = {
    "loaded": False, "available": False,
    "model": None, "corpus": None, "corpus_embeddings": None,
}


def _ensure_d3() -> Any:
    """Lazy-load D3 (DeBERTa prompt injection classifier). Returns pipeline or None."""
    if not _d3_state["loaded"]:
        _d3_state["loaded"] = True
        try:
            from transformers import pipeline as hf_pipeline
            pipe = hf_pipeline(
                "text-classification",
                model="protectai/deberta-v3-base-prompt-injection-v2",
                device=-1,
                truncation=True,
                max_length=512,
            )
            if hasattr(pipe.model, "eval"):
                pipe.model.eval()
            _d3_state["pipeline"] = pipe
            _d3_state["available"] = True
            log.info(
                "L1 D3 DeBERTa loaded",
                model="protectai/deberta-v3-base-prompt-injection-v2",
            )
        except Exception as e:
            _d3_state["available"] = False
            log.warning(
                "L1 D3 (DeBERTa) unavailable — deep semantic detection disabled",
                error=str(e),
                hint="pip install transformers torch",
            )
    return _d3_state["pipeline"] if _d3_state["available"] else None


def _ensure_d4() -> tuple[Any, Any] | None:
    """Lazy-load D4 (GPT-2 perplexity). Returns (model, tokenizer) or None."""
    if not _d4_state["loaded"]:
        _d4_state["loaded"] = True
        try:
            from transformers import GPT2LMHeadModel, GPT2TokenizerFast
            model = GPT2LMHeadModel.from_pretrained("gpt2")
            tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
            model.eval()
            _d4_state["model"] = model
            _d4_state["tokenizer"] = tokenizer
            _d4_state["available"] = True
            log.info("L1 D4 GPT-2 perplexity loaded")
        except Exception as e:
            _d4_state["available"] = False
            log.warning(
                "L1 D4 (GPT-2 perplexity) unavailable — perplexity detection disabled",
                error=str(e),
                hint="pip install transformers torch",
            )
    if _d4_state["available"]:
        return _d4_state["model"], _d4_state["tokenizer"]
    return None


def _load_jailbreak_corpus() -> list[dict[str, Any]]:
    """Load the D5 jailbreak template corpus from YAML."""
    try:
        with open(_CORPUS_PATH) as f:
            data = yaml.safe_load(f) or {}
        templates: list[dict[str, Any]] = []
        for category, entries in (data.get("categories") or {}).items():
            for entry in entries:
                if isinstance(entry, str):
                    templates.append({"category": category, "template": entry, "severity": 8})
                elif isinstance(entry, dict):
                    templates.append({
                        "category": category,
                        "template": entry["template"],
                        "severity": int(entry.get("severity", 8)),
                    })
        return templates
    except Exception as e:
        log.warning("D5 jailbreak corpus failed to load", path=str(_CORPUS_PATH), error=str(e))
        return []


def _ensure_d5() -> dict[str, Any] | None:
    """Lazy-load D5 (sentence-transformers MiniLM + jailbreak corpus)."""
    if not _d5_state["loaded"]:
        _d5_state["loaded"] = True
        try:
            import numpy as np
            from sentence_transformers import SentenceTransformer

            corpus = _load_jailbreak_corpus()
            if not corpus:
                _d5_state["available"] = False
                log.warning("L1 D5 unavailable — jailbreak corpus is empty")
                return None

            model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

            corpus_text = "|".join(c["template"] for c in corpus)
            corpus_sha = hashlib.sha256(corpus_text.encode("utf-8")).hexdigest()[:16]
            _EMBED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file = _EMBED_CACHE_DIR / f"jailbreak_corpus_{corpus_sha}.npy"

            if cache_file.exists():
                embeddings = np.load(cache_file)
                log.info("L1 D5 corpus embeddings loaded from cache", path=str(cache_file))
            else:
                embeddings = model.encode(
                    [c["template"] for c in corpus],
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                )
                np.save(cache_file, embeddings)
                log.info(
                    "L1 D5 corpus encoded and cached",
                    path=str(cache_file), templates=len(corpus),
                )

            _d5_state["model"] = model
            _d5_state["corpus"] = corpus
            _d5_state["corpus_embeddings"] = embeddings
            _d5_state["available"] = True
            log.info(
                "L1 D5 sentence-transformers loaded",
                model="sentence-transformers/all-MiniLM-L6-v2",
            )
        except Exception as e:
            _d5_state["available"] = False
            log.warning(
                "L1 D5 (sentence-transformers) unavailable — embedding similarity disabled",
                error=str(e),
                hint="sentence-transformers is a core dep; reinstall agentarmor-core",
            )
    return _d5_state if _d5_state["available"] else None


def normalize_and_disarm(text: str) -> tuple[str, list[str]]:
    """D1 protection step: Unicode normalization and content disarm."""
    anomalies = []

    # 1. Detect and strip zero-width chars
    zw_found = [c for c in text if c in ZERO_WIDTH_CHARS]
    if zw_found:
        anomalies.append(f"zero_width_chars:{len(zw_found)}_instances")
        text = ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)

    # 2. Detect RTL override (bidi attack)
    if '‮' in text or '‭' in text:
        anomalies.append("bidi_override_detected")
        text = text.replace('‮', '').replace('‭', '')

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


def _classify_with_d3_sync(text: str) -> tuple[str, float]:
    """Synchronous D3 inference."""
    pipe = _ensure_d3()
    if pipe is None:
        return ("UNKNOWN", 0.0)
    result = pipe(text[:512])[0]
    label = _DEBERTA_LABEL_MAP.get(result["label"], result["label"])
    return label, float(result["score"])


def _compute_perplexity_sync(text: str) -> float:
    """Synchronous D4 inference."""
    state = _ensure_d4()
    if state is None or len(text) < 20:
        return 0.0
    import torch
    model, tokenizer = state
    inputs = tokenizer(text[:200], return_tensors="pt", truncation=True)
    with torch.no_grad():
        outputs = model(**inputs, labels=inputs["input_ids"])
    return float(torch.exp(outputs.loss).item())


def _embedding_similarity_sync(text: str) -> dict[str, Any] | None:
    """Synchronous D5 embedding similarity.

    Returns {max_similarity, matched_template, matched_category, severity} or None.
    """
    state = _ensure_d5()
    if state is None:
        return None
    import numpy as np
    model = state["model"]
    corpus = state["corpus"]
    corpus_emb = state["corpus_embeddings"]
    query_emb = model.encode(
        [text[:512]], convert_to_numpy=True, normalize_embeddings=True,
    )[0]
    sims = corpus_emb @ query_emb
    idx = int(np.argmax(sims))
    return {
        "max_similarity": float(sims[idx]),
        "matched_template": corpus[idx]["template"],
        "matched_category": corpus[idx]["category"],
        "severity": int(corpus[idx].get("severity", 8)),
    }


async def classify_with_prompt_guard(text: str) -> tuple[str, float]:
    """D3 entry point: async wrapper with timeout."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_classify_with_d3_sync, text),
            timeout=_MODEL_TIMEOUT_S,
        )
    except TimeoutError:
        log.warning("L1 D3 inference timed out", timeout_s=_MODEL_TIMEOUT_S)
        return ("UNKNOWN", 0.0)


async def compute_perplexity(text: str) -> float:
    """D4 entry point: async wrapper with timeout."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_compute_perplexity_sync, text),
            timeout=_MODEL_TIMEOUT_S,
        )
    except TimeoutError:
        log.warning("L1 D4 inference timed out", timeout_s=_MODEL_TIMEOUT_S)
        return 0.0


async def embedding_similarity(text: str) -> dict[str, Any] | None:
    """D5 entry point: async wrapper with timeout."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_embedding_similarity_sync, text),
            timeout=_MODEL_TIMEOUT_S,
        )
    except TimeoutError:
        log.warning("L1 D5 inference timed out", timeout_s=_MODEL_TIMEOUT_S)
        return None


class IngestionLayer(SecurityLayer):
    name = "L1_ingestion"

    _startup_log_done = False

    def __init__(self, config: IngestionConfig | None = None):
        self.config = config or IngestionConfig()
        self._log_startup_status()

    def _log_startup_status(self) -> None:
        """One-shot startup log explaining which L1 detectors are enabled."""
        if IngestionLayer._startup_log_done:
            return
        IngestionLayer._startup_log_done = True
        if self.config.embedding_similarity:
            log.info(
                "L1 embedding-similarity (D5) enabled — MiniLM weights (~80MB) "
                "will download on first request"
            )
        else:
            log.info("L1 embedding-similarity (D5) disabled in config")
        if self.config.deep_semantic:
            log.info(
                "L1 deep-semantic (D3 DeBERTa + D4 GPT-2) enabled — "
                "weights (~1.2GB) will download on first request, "
                "adds ~200-500ms latency per check"
            )
        else:
            log.info(
                "L1 deep-semantic (D3 DeBERTa + D4 GPT-2) disabled by default for performance. "
                "Enable in agentarmor.yaml [ingestion.deep_semantic=true] for maximum security."
            )

    async def process(self, event: AgentEvent) -> LayerResult:
        start_time = time.time()

        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")

        input_text = self._extract_text(event)
        if len(input_text.encode()) > self.config.max_input_size_bytes:
            return LayerResult(
                layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.HIGH,
                message=(
                    f"Input exceeds max size "
                    f"({len(input_text.encode())} > {self.config.max_input_size_bytes} bytes)"
                ),
            )

        details: dict[str, Any] = {
            "vector": event.metadata.get("source", "user_input"),
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

        # --- D2 Syntactic Patterns ---
        d2_hits: list[str] = []
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
                        "matched_text": match.group()[:100],
                    })
                    threat_score = max(threat_score, sev)
                    break

        details["defenses_applied"].append("D2")

        # --- D5 Embedding Similarity (default-on, lightweight) ---
        if self.config.embedding_similarity:
            details["defenses_applied"].append("D5")
            d5_result = await embedding_similarity(normalized)
            if d5_result is not None:
                sim = d5_result["max_similarity"]
                details["embedding_similarity"] = sim
                details["embedding_match_template"] = d5_result["matched_template"]
                details["embedding_match_category"] = d5_result["matched_category"]
                if sim >= 0.85:
                    details["anomalies_found"].append({
                        "type": "embedding_similarity",
                        "category": d5_result["matched_category"],
                        "severity": d5_result["severity"],
                        "confidence": sim,
                        "matched_template": d5_result["matched_template"],
                    })
                    threat_score = max(threat_score, d5_result["severity"])
                elif sim >= 0.70:
                    details["anomalies_found"].append({
                        "type": "embedding_similarity_candidate",
                        "category": d5_result["matched_category"],
                        "severity": 5,
                        "confidence": sim,
                        "matched_template": d5_result["matched_template"],
                    })
                    threat_score = max(threat_score, 5)

        # --- D3 + D4 Deep Semantic (opt-in via deep_semantic) ---
        pg_label = "UNKNOWN"
        if self.config.deep_semantic:
            details["defenses_applied"].append("D3")
            pg_label, pg_score = await classify_with_prompt_guard(normalized)
            details["classifier_label"] = pg_label
            details["classifier_confidence"] = pg_score

            if pg_label in ("INJECTION", "JAILBREAK"):
                if pg_score >= 0.85:
                    details["anomalies_found"].append({
                        "type": "classifier_injection",
                        "category": "jailbreak_semantic",
                        "severity": 8,
                        "confidence": pg_score,
                    })
                    threat_score = max(threat_score, 8)
                elif pg_score >= 0.70:
                    details["anomalies_found"].append({
                        "type": "classifier_injection_candidate",
                        "category": "jailbreak_semantic",
                        "severity": 5,
                        "confidence": pg_score,
                    })
                    threat_score = max(threat_score, 5)

            # D4 — perplexity. Same prompt -> same verdict regardless of source metadata.
            details["defenses_applied"].append("D4")
            ppl = await compute_perplexity(normalized)
            details["perplexity_score"] = ppl
            token_count = len(normalized.split())
            if ppl > 1000 and token_count < 200:
                details["anomalies_found"].append({
                    "type": "high_perplexity",
                    "category": "gcg_adversarial_suffix_candidate",
                    "severity": 7,
                    "matched_text": f"Perplexity: {ppl}",
                })
                if d2_hits or pg_label in ("INJECTION", "JAILBREAK"):
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
            details=details,
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
