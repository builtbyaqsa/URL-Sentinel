import re
import math
from collections import Counter
from urllib.parse import urlparse, parse_qs


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features(url: str) -> dict:

    url = str(url).strip()
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Existing features
    url_length = len(url)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_at = url.count("@")
    has_https = int(parsed.scheme.lower() == "https")

    ip_pattern = r"^\d{1,3}(?:\.\d{1,3}){3}$"
    has_ip = int(bool(re.fullmatch(ip_pattern, hostname)))

    keywords = [
        "login", "verify", "update",
        "account", "banking", "secure", "signin"
    ]

    has_suspicious_keyword = int(
        any(keyword in url.lower() for keyword in keywords)
    )

    # Advanced features
    domain_length = len(hostname)

    subdomain_count = max(
        0, len(hostname.split(".")) - 2
    ) if hostname else 0

    url_entropy = calculate_entropy(url)

    num_digits = sum(char.isdigit() for char in url)

    special_char_count = sum(
        not char.isalnum() for char in url
    )

    path_length = len(path)

    query_param_count = len(parse_qs(query))

    has_encoded_chars = int(
        bool(re.search(r"%[0-9a-fA-F]{2}", url))
    )

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "has_https": has_https,
        "has_ip": has_ip,
        "has_suspicious_keyword": has_suspicious_keyword,
        "domain_length": domain_length,
        "subdomain_count": subdomain_count,
        "url_entropy": url_entropy,
        "num_digits": num_digits,
        "special_char_count": special_char_count,
        "path_length": path_length,
        "query_param_count": query_param_count,
        "has_encoded_chars": has_encoded_chars
    }