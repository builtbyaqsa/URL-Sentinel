import re
from urllib.parse import urlparse
from services import check_threat_feed

def analyze_url_heuristics(url: str):
    flags = []
    score = 0
    max_score = 10

    if not url.startswith("https://"):
        score += 2
        flags.append("Missing HTTPS connection")

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""

    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, hostname):
        score += 3
        flags.append("Direct IP address used instead of domain")

    suspicious_keywords = ["verify", "login", "banking", "update", "account", "secure", "signin"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            score += 2
            flags.append(f"Suspicious keyword detected: '{keyword}'")
            break

    if hostname.count(".") > 3:
        score += 3
        flags.append("Excessive subdomains detected")

    if check_threat_feed(url):
        score += 5
        flags.append("CRITICAL: URL found in Live Threat Feed Database")

    is_suspicious = score >= 4

    return {
        "url": url,
        "risk_score": min(score, max_score),
        "max_score": max_score,
        "is_suspicious": is_suspicious,
        "detected_flags": flags
    }