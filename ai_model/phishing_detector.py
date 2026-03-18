from urllib.parse import urlparse
from ai_model.whois_checker import check_domain_age
import re

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "bank", "signin", "confirm", "password"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
]

def analyze_url(url: str):
    score = 0
    reasons = []

    # 1. URL length check
    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    # 2. IP address in URL
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("IP address used instead of domain")

    # 3. Suspicious keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword found: '{word}'")

    # 4. URL shortener
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    for short in SHORTENERS:
        if short in domain:
            score += 20
            reasons.append("URL uses a link shortener")

    return score, reasons
def classify_url(url: str):
    score, reasons = analyze_url(url)

    # WHOIS DOMAIN AGE CHECK
    domain = urlparse(url).netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    age_days, whois_score, whois_reason = check_domain_age(domain)
    score += whois_score

    if whois_reason:
        reasons.append(whois_reason)

    # FINAL VERDICT
    if score >= 70:
        verdict = "PHISHING"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "risk_score": min(score, 100),
        "reasons": reasons
    }

