from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "URL-Sentinel API"}

def test_scan_safe_url():
    response = client.post("/scan", json={"url": "https://google.com"})
    assert response.status_code == 200

def test_metrics_unauthorized():
    response = client.get("/metrics")
    assert response.status_code == 403

def test_metrics_authorized():
    response = client.get("/metrics", headers={"X-API-Key": "sentinel-secret-key-123"})
    assert response.status_code == 200