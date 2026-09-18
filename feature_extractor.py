import re
from urllib.parse import urlparse

def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    
    # Lexical Feature Extraction
    url_length = len(url)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_at = url.count('@')
    has_https = 1 if parsed.scheme == 'https' else 0
    
    # Check for direct IP address in domain
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    has_ip = 1 if re.match(ip_pattern, hostname.split(':')[0]) else 0
    
    # Suspicious keywords search
    keywords = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'signin']
    has_suspicious_keyword = 1 if any(kw in url.lower() for kw in keywords) else 0
    
    return {
        'url_length': url_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_at': num_at,
        'has_https': has_https,
        'has_ip': has_ip,
        'has_suspicious_keyword': has_suspicious_keyword
    }
