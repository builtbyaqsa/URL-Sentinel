from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] in ["healthy", "unhealthy"]

def test_scan_url_threat_intel():
    response = client.post("/scan", json={"url": "http://phish-account-update.com"})
    assert response.status_code == 200

def test_get_scans_history():
    response = client.get("/scans")
    assert response.status_code == 200
    assert "scans" in response.json()