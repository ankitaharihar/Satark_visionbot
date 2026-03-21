# -*- coding: utf-8 -*-
"""LLM-style URL phishing analyzer using Hugging Face zero-shot inference."""

import os
from typing import Any, Dict, Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()

HF_TOKEN = os.getenv("HF_TOKEN")
ZERO_SHOT_MODEL_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"


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


def analyze_url_with_llm(url: str) -> Dict[str, Any]:
    """Analyze URL using zero-shot classification with phishing/safe labels."""
    if not HF_TOKEN:
        return {
            "label": None,
            "confidence": None,
            "error": "HF_TOKEN not set",
        }

    headers = {
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type": "application/json",
    }

    input_text = (
        "Classify this URL as phishing or safe based on cybersecurity context. "
        f"URL: {url}"
    )
    payload = {
        "inputs": input_text,
        "parameters": {
            "candidate_labels": ["phishing", "safe"],
            "multi_label": False,
        },
    }

    try:
        response = requests.post(
            ZERO_SHOT_MODEL_URL,
            headers=headers,
            json=payload,
            timeout=20,
        )
    except Exception as exc:
        return {
            "label": None,
            "confidence": None,
            "error": str(exc),
        }

    if response.status_code == 503:
        return {
            "label": None,
            "confidence": None,
            "error": "Zero-shot model is loading, try again",
        }

    if response.status_code != 200:
        return {
            "label": None,
            "confidence": None,
            "error": f"HF API error: {response.status_code}",
        }

    label, confidence, parse_error = _normalize_zero_shot_result(response.json())
    if parse_error:
        return {
            "label": None,
            "confidence": None,
            "error": parse_error,
        }

    normalized_label = "PHISHING" if label == "phishing" else "SAFE" if label == "safe" else None
    return {
        "label": normalized_label,
        "confidence": round(confidence, 1) if confidence is not None else None,
        "error": None,
    }
