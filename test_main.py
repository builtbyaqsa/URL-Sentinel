from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "URL-Sentinel"}

def test_scan_url():
    response = client.post(
        "/scan",
        json={"url": "http://192.168.1.1/login-verify-account"}
    )
    assert response.status_code == 200
    assert "risk_score" in response.json()
    assert "is_malicious" in response.json()

def test_metrics_unauthorized():
    response = client.get("/metrics")
    assert response.status_code == 401

def test_metrics_authorized():
    response = client.get(
        "/metrics",
        headers={"x-api-key": "sentinel-secret-key-2026"}
    )
    assert response.status_code == 200
    assert "total_scans_processed" in response.json()