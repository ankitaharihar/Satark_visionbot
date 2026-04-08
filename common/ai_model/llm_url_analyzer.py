# -*- coding: utf-8 -*-
"""LLM-style URL phishing analyzer using Hugging Face zero-shot inference."""

import os
from urllib.parse import urlparse
from typing import Any, Dict, Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()

HF_TOKEN = os.getenv("HF_TOKEN")
ZERO_SHOT_MODEL_URLS = [
    os.getenv("ZERO_SHOT_MODEL_URL", "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"),
    os.getenv("ZERO_SHOT_MODEL_URL_2", "https://api-inference.huggingface.co/models/MoritzLaurer/deberta-v3-large-zeroshot-v2.0"),
]


def _normalize_zero_shot_result(result: Any) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """Normalize varying HF response formats into label/confidence/error tuple."""
    if isinstance(result, dict) and result.get("error"):
        return None, None, str(result["error"])

    if isinstance(result, dict) and "labels" in result and "scores" in result:
        labels = result.get("labels") or []
        scores = result.get("scores") or []
        if labels and scores:
            label = str(labels[0]).strip().lower()
            confidence = float(scores[0]) * 100.0
            return label, confidence, None

    if isinstance(result, list) and result:
        first_item = result[0]
        if isinstance(first_item, dict) and "labels" in first_item and "scores" in first_item:
            labels = first_item.get("labels") or []
            scores = first_item.get("scores") or []
            if labels and scores:
                label = str(labels[0]).strip().lower()
                confidence = float(scores[0]) * 100.0
                return label, confidence, None

    return None, None, "Unexpected model response format"


def _build_context_input(url: str) -> str:
    """Build richer cybersecurity context for better zero-shot classification."""
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":")[0]
    path_q = (parsed.path or "") + (f"?{parsed.query}" if parsed.query else "")
    keywords = [
        "login", "verify", "update", "secure", "account", "password",
        "signin", "bank", "payment", "suspended", "urgent", "confirm",
    ]
    found = [k for k in keywords if k in url.lower()]

    return (
        "Cybersecurity task: classify URL as phishing or safe. "
        "Phishing usually includes brand impersonation, credential theft intent, urgent language, "
        "suspicious host/path patterns, or deceptive domains.\n"
        f"URL: {url}\n"
        f"Host: {host}\n"
        f"PathAndQuery: {path_q}\n"
        f"SuspiciousKeywordsInURL: {', '.join(found) if found else 'none'}"
    )


def _query_zero_shot_model(url: str, model_url: str) -> Dict[str, Any]:
    """Run one zero-shot model and normalize output."""
    headers = {
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "inputs": _build_context_input(url),
        "parameters": {
            "candidate_labels": ["phishing", "safe"],
            "multi_label": False,
            "hypothesis_template": "This URL is {}.",
        },
    }

    try:
        response = requests.post(model_url, headers=headers, json=payload, timeout=20)
    except Exception as exc:
        return {"model": model_url, "label": None, "confidence": None, "error": str(exc)}

    if response.status_code == 503:
        return {
            "model": model_url,
            "label": None,
            "confidence": None,
            "error": "Model loading",
        }

    if response.status_code != 200:
        return {
            "model": model_url,
            "label": None,
            "confidence": None,
            "error": f"HF API error: {response.status_code}",
        }

    label, confidence, parse_error = _normalize_zero_shot_result(response.json())
    if parse_error:
        return {
            "model": model_url,
            "label": None,
            "confidence": None,
            "error": parse_error,
        }

    normalized_label = "PHISHING" if label == "phishing" else "SAFE" if label == "safe" else None
    return {
        "model": model_url,
        "label": normalized_label,
        "confidence": round(confidence, 1) if confidence is not None else None,
        "error": None,
    }


def analyze_url_with_llm(url: str) -> Dict[str, Any]:
    """Analyze URL using an ensemble of zero-shot models with confidence-weighted voting."""
    if not HF_TOKEN:
        return {
            "label": None,
            "confidence": None,
            "error": "HF_TOKEN not set",
            "model_votes": [],
            "ensemble_strength": 0.0,
        }

    votes = []
    for model_url in ZERO_SHOT_MODEL_URLS:
        if not model_url:
            continue
        votes.append(_query_zero_shot_model(url, model_url))

    ok_votes = [v for v in votes if not v.get("error") and v.get("label") in {"PHISHING", "SAFE"}]
    if not ok_votes:
        errors = [v.get("error") for v in votes if v.get("error")]
        err_text = "; ".join([e for e in errors if e]) or "No model response"
        return {
            "label": None,
            "confidence": None,
            "error": err_text,
            "model_votes": votes,
            "ensemble_strength": 0.0,
        }

    phishing_weight = sum(float(v.get("confidence") or 0.0) for v in ok_votes if v.get("label") == "PHISHING")
    safe_weight = sum(float(v.get("confidence") or 0.0) for v in ok_votes if v.get("label") == "SAFE")
    total_weight = max(0.1, phishing_weight + safe_weight)

    if phishing_weight > safe_weight:
        final_label = "PHISHING"
        final_conf = (phishing_weight / total_weight) * 100.0
    else:
        final_label = "SAFE"
        final_conf = (safe_weight / total_weight) * 100.0

    strength = abs(phishing_weight - safe_weight) / total_weight * 100.0

    # If models are close/uncertain, mark as no-decision to avoid overconfident mistakes.
    if strength < 8.0 and final_conf < 65.0:
        return {
            "label": None,
            "confidence": round(final_conf, 1),
            "error": "Model disagreement on classification",
            "model_votes": votes,
            "ensemble_strength": round(strength, 1),
        }

    return {
        "label": final_label,
        "confidence": round(final_conf, 1),
        "error": None,
        "model_votes": votes,
        "ensemble_strength": round(strength, 1),
    }
