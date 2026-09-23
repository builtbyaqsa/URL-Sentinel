def check_threat_intelligence(url: str) -> dict:
    phish_indicators = ['phish', 'malicious', 'login-verify', 'account-update']
    for indicator in phish_indicators:
        if indicator in url.lower():
            return {'threat_found': True, 'feed': 'PhishTank Feeds', 'verdict': 'Malicious'}
    return {'threat_found': False, 'feed': 'PhishTank Feeds', 'verdict': None}
