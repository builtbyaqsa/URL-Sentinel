from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "URL-Sentinel API is running"}

def test_scan_suspicious_url():
    response = client.post("/scan", json={"url": "http://192.168.1.1/verify/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] == True
    assert data["risk_score"] > 0

def test_scan_safe_url():
    response = client.post("/scan", json={"url": "https://google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] == False

def test_threat_feed_detection():
    response = client.post("/scan", json={"url": "http://login-verification-paypal.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] == True
    assert "CRITICAL: URL found in Live Threat Feed Database" in data["detected_flags"]