from feature_extractor import extract_features

def test_extract_features_legitimate():
    res = extract_features('https://google.com')
    assert res['has_https'] == 1
    assert res['has_ip'] == 0
    assert res['has_suspicious_keyword'] == 0

def test_extract_features_suspicious():
    res = extract_features('http://192.168.1.1/login-verify-account')
    assert res['has_https'] == 0
    assert res['has_ip'] == 1
    assert res['has_suspicious_keyword'] == 1
