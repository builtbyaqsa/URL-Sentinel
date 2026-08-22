import re
from urllib.parse import urlparse

def analyze_url_heuristics(url: str):
    flags = []
    score = 0
    max_score = 10

    # Rule 1: Missing HTTPS connection
    if not url.startswith("https://"):
        score += 2
        flags.append("Missing HTTPS connection")

    # Extract hostname using urllib
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""

    # Rule 2: IP Address used instead of Domain Name
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, hostname):
        score += 3
        flags.append("Direct IP address used instead of domain")

    # Rule 3: Suspicious Keywords in URL
    suspicious_keywords = ["verify", "login", "banking", "update", "account", "secure", "signin"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            score += 2
            flags.append(f"Suspicious keyword detected: '{keyword}'")
            break

    # Rule 4: Excessive Subdomains / Dots in Hostname
    if hostname.count(".") > 3:
        score += 3
        flags.append("Excessive subdomains detected")

    is_suspicious = score >= 4

    return {
        "url": url,
        "risk_score": score,
        "max_score": max_score,
        "is_suspicious": is_suspicious,
        "detected_flags": flags
    }