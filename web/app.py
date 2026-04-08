# -*- coding: utf-8 -*-
"""Flask web app + API wrapper for Satark phishing detection."""

import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from common.ai_model.phishing_detector import classify_url
from common.bot_enhancements import (
    check_threat_intel,
    init_analysis_db,
    save_analysis_log_sqlite,
)

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)


def _compute_final_result(url: str):
    result = classify_url(url)
    domain = urlparse(url).netloc.lower().replace("www.", "")
    threat_intel = check_threat_intel(url, domain)

    final_score = min(100, int(result.get("risk_score", 0)) + int(threat_intel.get("risk_score", 0)))

    if threat_intel.get("is_malicious") and result.get("verdict") != "PHISHING":
        final_verdict = "PHISHING"
    elif final_score >= 70:
        final_verdict = "PHISHING"
    elif final_score >= 40:
        final_verdict = "SUSPICIOUS"
    else:
        final_verdict = "SAFE"

    return {
        "url": url,
        "domain": domain,
        "final_verdict": final_verdict,
        "final_score": final_score,
        "model_result": result,
        "threat_intel": threat_intel,
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/analyze")
def analyze_url_api():
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()

    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        return jsonify({"ok": False, "error": "Please provide a valid URL starting with http:// or https://"}), 400

    try:
        data = _compute_final_result(url)

        save_analysis_log_sqlite(
            url=url,
            analysis={
                "risk_score": data["final_score"],
                "verdict": data["final_verdict"],
                "ai_label": data["model_result"].get("ai_label"),
                "ai_confidence": data["model_result"].get("ai_confidence"),
                "llm_label": data["model_result"].get("llm_label"),
                "llm_confidence": data["model_result"].get("llm_confidence"),
                "threat_sources": data["threat_intel"].get("sources", []),
                "reasons": data["model_result"].get("reasons", []),
            },
            user_id=0,
        )

        return jsonify({"ok": True, "data": data})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


if __name__ == "__main__":
    init_analysis_db()
    host = os.getenv("WEB_API_HOST", "127.0.0.1")
    port = int(os.getenv("WEB_API_PORT", "8000"))
    debug = os.getenv("WEB_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
