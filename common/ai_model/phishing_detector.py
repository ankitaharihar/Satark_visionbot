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
from common.ai_model.llm_url_analyzer import analyze_url_with_llm

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

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "zip", "country"
}

# Canonical brand hostnames used for simple anti-typosquatting checks.
TRUSTED_BRAND_DOMAINS = {
    "google": ["google.com"],
    "github": ["github.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "telegram": ["telegram.org"],
    "whatsapp": ["whatsapp.com"],
}


def _levenshtein_distance(a: str, b: str) -> int:
    """Compute edit distance for typosquatting detection."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = curr[j - 1] + 1
            delete_cost = prev[j] + 1
            replace_cost = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev = curr
    return prev[-1]


def _extract_host_and_base(domain: str):
    """Extract host and approximate base label from a domain/netloc string."""
    host = domain.lower().split(":")[0].strip(".")
    labels = [p for p in host.split(".") if p]
    base = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    tld = labels[-1] if labels else ""
    return host, base, tld, labels


def detect_typosquatting(domain: str):
    """Detect likely typosquatted brand domains (e.g., githube.com)."""
    host, base, _, _ = _extract_host_and_base(domain)
    findings = []

    for brand, trusted_domains in TRUSTED_BRAND_DOMAINS.items():
        # Legit brand-owned domain suffix should not be penalized.
        if any(host == d or host.endswith(f".{d}") for d in trusted_domains):
            continue

        dist = _levenshtein_distance(base, brand)
        if dist == 1:
            findings.append(f"Possible typosquatting: '{base}' looks like '{brand}'")
            continue

        if base.startswith(brand) and 0 < (len(base) - len(brand)) <= 2:
            findings.append(f"Possible brand mimicry: '{base}' extends '{brand}'")

    return findings


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
    domain_lower = domain.lower().split(":")[0]
    detected_brands = []
    _, base_label, _, _ = _extract_host_and_base(domain_lower)

    for brand in BRAND_KEYWORDS:
        if brand in url_lower and brand != base_label:
            # Brand mention in URL but primary domain label is different.
            if brand not in base_label:
                detected_brands.append(brand)

        # Brand keyword appears somewhere in host but is not the base label.
        if brand in domain_lower and brand != base_label and brand not in detected_brands:
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
    host, base_label, tld, labels = _extract_host_and_base(domain)

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

    # 4b. Suspicious TLD and hostname tricks
    if tld in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"Suspicious top-level domain '.{tld}'")

    if "xn--" in host:
        score += 20
        reasons.append("Punycode domain detected (possible homograph attack)")

    # Too many subdomains are often used to look legitimate at a glance.
    if len(labels) >= 4:
        score += 10
        reasons.append("Domain has many subdomains")

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

    # 7b. Typosquatting detection
    typo_findings = detect_typosquatting(domain)
    details["typosquatting_findings"] = typo_findings
    if typo_findings:
        score += 60
        reasons.extend(typo_findings)

    # 8. AI Model Classification
    ai_label, ai_confidence = ai_classify_url(url)
    details["ai_label"] = ai_label
    details["ai_confidence"] = ai_confidence

    if ai_label == "PHISHING":
        ai_conf = float(ai_confidence or 0.0)
        ai_add = int(max(15, min(45, ai_conf * 0.45)))
        score += ai_add
        reasons.append(
            f"AI model flagged as phishing ({ai_confidence}% confidence, +{ai_add} risk)"
        )
    elif ai_label == "SAFE":
        ai_conf = float(ai_confidence or 0.0)
        ai_reduce = int(max(3, min(12, ai_conf * 0.12)))
        score = max(0, score - ai_reduce)

    # 9. Zero-shot AI Model Classification
    llm_result = analyze_url_with_llm(url)
    llm_label = llm_result.get("label")
    llm_confidence = llm_result.get("confidence")
    llm_error = llm_result.get("error")
    llm_strength = llm_result.get("ensemble_strength")
    llm_votes = llm_result.get("model_votes") or []

    details["llm_label"] = llm_label
    details["llm_confidence"] = llm_confidence
    details["llm_error"] = llm_error
    details["llm_strength"] = llm_strength
    details["llm_votes"] = llm_votes

    if llm_label == "PHISHING":
        llm_conf = float(llm_confidence or 0.0)
        llm_add = int(max(10, min(35, llm_conf * 0.35)))
        if isinstance(llm_strength, (int, float)) and llm_strength >= 40:
            llm_add += 5
        score += llm_add
        reasons.append(
            f"Zero-shot AI flagged phishing ({llm_confidence}% confidence, +{llm_add} risk)"
        )
    elif llm_label == "SAFE":
        llm_conf = float(llm_confidence or 0.0)
        llm_reduce = int(max(2, min(8, llm_conf * 0.08)))
        score = max(0, score - llm_reduce)
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