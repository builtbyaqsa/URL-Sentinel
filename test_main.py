from fastapi.testclient import TestClient
from app import app

# API ko test karne ke liye client tayar kar rahe hain
client = TestClient(app)

def test_home_endpoint():
    # Root URL (/) ko test kar rahe hain
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "URL-Sentinel API is running"}

def test_suspicious_url_detection():
    # Unencrypted IP address wali link ko test kar rahe hain
    payload = {"url": "http://192.168.1.1/update-login"}
    response = client.post("/scan", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] is True
    assert data["risk_score"] >= 3

def test_safe_url_detection():
    # Normal secure domain ko test kar rahe hain
    payload = {"url": "https://google.com"}
    response = client.post("/scan", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] is False
    assert data["risk_score"] == 0