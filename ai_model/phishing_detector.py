# -*- coding: utf-8 -*-
"""
Phishing Detector - AI Enhanced
Uses HuggingFace model + heuristics + SSL + WHOIS + Brand detection
"""
import os
import re
import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv
from ai_model.llm_url_analyzer import analyze_url_with_llm

load_dotenv()

HF_TOKEN = os.getenv("HF_TOKEN")
HF_API_URL = "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing"

# Known brands for impersonation detection
BRAND_KEYWORDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "bank", "twitter", "linkedin", "whatsapp",
    "telegram", "hdfc", "sbi", "icici", "axis", "paytm", "upi"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "credential", "suspended", "urgent",
    "click", "free", "winner", "prize", "lucky", "offer"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "rebrand.ly", "cutt.ly"
]


def check_ssl(domain):
    """Check SSL certificate validity"""
    ssl_info = {
        "valid": False,
        "issuer": "Unknown",
        "expires": "Unknown",
        "risk_score": 0,
        "reason": None
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            ssl_info["valid"] = True
            # Get issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            ssl_info["issuer"] = issuer.get("organizationName", "Unknown")
            # Get expiry
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                ssl_info["expires"] = expire_date.strftime("%Y-%m-%d")
                days_left = (expire_date - datetime.utcnow()).days
                if days_left < 7:
                    ssl_info["risk_score"] += 30
                    ssl_info["reason"] = f"SSL expires in {days_left} days"
    except ssl.SSLCertVerificationError:
        ssl_info["risk_score"] = 25
        ssl_info["reason"] = "Invalid/Self-signed SSL certificate"
    except Exception:
        ssl_info["risk_score"] = 10
        ssl_info["reason"] = "SSL check failed"
    return ssl_info


def check_domain_age(domain):
    """Check domain age via WHOIS"""
    try:
        import whois
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days < 7:
                return age_days, 40, f"Domain only {age_days} days old — very new!"
            elif age_days < 30:
                return age_days, 30, f"Domain only {age_days} days old — recently registered"
            elif age_days < 90:
                return age_days, 20, f"Domain is {age_days} days old — relatively new"
            return age_days, 0, None
        return None, 20, "Domain creation date not found"
    except Exception:
        return None, 15, "WHOIS lookup failed"


def check_brand_impersonation(url, domain):
    """Check if URL impersonates known brands"""
    url_lower = url.lower()
    domain_lower = domain.lower()
    detected_brands = []

    for brand in BRAND_KEYWORDS:
        if brand in url_lower:
            # If brand name in URL but not in domain (e.g. paypal.secure-login.com)
            if brand not in domain_lower.split(".")[0]:
                detected_brands.append(brand)

    return detected_brands


def ai_classify_url(url):
    """Use HuggingFace BERT model to classify URL"""
    if not HF_TOKEN:
        return None, "HF_TOKEN not set"

    try:
        headers = {"Authorization": f"Bearer {HF_TOKEN}"}
        payload = {"inputs": url}
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=15)

        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list) and len(result) > 0:
                predictions = result[0]
                # Get highest confidence label
                best = max(predictions, key=lambda x: x["score"])
                label = best["label"].upper()
                confidence = round(best["score"] * 100, 1)
                return label, confidence
        elif response.status_code == 503:
            return None, "Model loading, please retry"
        else:
            return None, f"API error: {response.status_code}"
    except Exception as e:
        return None, str(e)


def classify_url(url: str):
    """Main classification function"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    score = 0
    reasons = []
    details = {}

    # 1. URL Length
    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    # 2. IP Address in URL
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 25
        reasons.append("IP address used instead of domain")

    # 3. Suspicious Keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword: '{word}'")

    # 4. URL Shortener
    for short in SHORTENERS:
        if short in domain:
            score += 20
            reasons.append("URL uses a link shortener")

    # 5. SSL Check
    ssl_info = check_ssl(domain)
    details["ssl"] = ssl_info
    if ssl_info["risk_score"] > 0:
        score += ssl_info["risk_score"]
        if ssl_info["reason"]:
            reasons.append(f"SSL: {ssl_info['reason']}")

    # 6. WHOIS Domain Age
    age_days, whois_score, whois_reason = check_domain_age(domain)
    details["domain_age"] = age_days
    score += whois_score
    if whois_reason:
        reasons.append(whois_reason)

    # 7. Brand Impersonation
    brands = check_brand_impersonation(url, domain)
    details["impersonated_brands"] = brands
    if brands:
        score += 30
        reasons.append(f"Brand impersonation detected: {', '.join(brands)}")

    # 8. AI Model Classification
    ai_label, ai_confidence = ai_classify_url(url)
    details["ai_label"] = ai_label
    details["ai_confidence"] = ai_confidence

    if ai_label == "PHISHING":
        score += 35
        reasons.append(f"AI model flagged as phishing ({ai_confidence}% confidence)")
    elif ai_label == "SAFE":
        score = max(0, score - 10)

    # 9. Zero-shot AI Model Classification
    llm_result = analyze_url_with_llm(url)
    llm_label = llm_result.get("label")
    llm_confidence = llm_result.get("confidence")
    llm_error = llm_result.get("error")

    details["llm_label"] = llm_label
    details["llm_confidence"] = llm_confidence
    details["llm_error"] = llm_error

    if llm_label == "PHISHING":
        score += 25
        reasons.append(
            f"Zero-shot AI model flagged as phishing ({llm_confidence}% confidence)"
        )
    elif llm_label == "SAFE":
        score = max(0, score - 5)
    elif llm_error:
        reasons.append(f"Zero-shot AI model unavailable: {llm_error}")

    if ai_label and llm_label and ai_label != llm_label:
        reasons.append("AI models disagree, applying cautious scoring")
        score += 5

    # Final Verdict
    score = min(score, 100)
    if score >= 70:
        verdict = "PHISHING"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
        "ssl_info": ssl_info,
        "domain_age": age_days,
        "impersonated_brands": brands,
        "ai_label": ai_label,
        "ai_confidence": ai_confidence,
        "llm_label": llm_label,
        "llm_confidence": llm_confidence,
        "llm_error": llm_error,
    }