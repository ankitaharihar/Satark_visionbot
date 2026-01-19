import whois
from datetime import datetime

def check_domain_age(domain: str):
    """
    Returns:
      age_days (int)
      risk_score (int)
      reason (str or None)
    """
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0, 20, "Domain creation date not found"

        age_days = (datetime.now() - creation_date).days

        if age_days < 7:
            return age_days, 40, "Domain registered less than 7 days ago"
        elif age_days < 30:
            return age_days, 30, "Domain registered less than 30 days ago"
        elif age_days < 90:
            return age_days, 20, "Domain registered less than 3 months ago"
        else:
            return age_days, 0, None

    except Exception:
        return 0, 15, "WHOIS lookup failed"
