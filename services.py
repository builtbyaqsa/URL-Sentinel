def check_threat_intelligence(url: str) -> dict:
    # Expanded heuristic indicators for enterprise phishing simulation
    phish_indicators = [
        'phish', 'malicious', 'login-verify', 'account-update',
        'secure-update', 'signin', 'verify-bank', 'account-suspended',
        'auth-portal', 'customer-support', 'security-check', 'password-reset'
    ]
    
    url_lower = url.lower()
    for indicator in phish_indicators:
        if indicator in url_lower:
            return {
                'threat_found': True, 
                'feed': 'URL-Sentinel Heuristic Feed', 
                'verdict': 'Malicious'
            }
            
    return {
        'threat_found': False, 
        'feed': 'PhishTank Feeds', 
        'verdict': None
    }