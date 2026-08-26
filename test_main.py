from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_scan_safe_url():
    response = client.post("/scan", json={"url": "https://google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"] is False

def test_scan_phishing_url():
    response = client.post("/scan", json={"url": "http://192.168.1.1/login-verify"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"] is True

def test_scan_threat_feed_match():
    response = client.post("/scan", json={"url": "http://malicious-phishing-site.com/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"] is True

def test_metrics_endpoint():
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "threats_detected" in data
    assert "safe_urls" in data