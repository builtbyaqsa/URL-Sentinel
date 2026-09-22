from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_read_root():
    response = client.get('/')
    assert response.status_code == 200

def test_scan_url():
    response = client.post('/scan', json={'url': 'http://example.com'})
    assert response.status_code == 200
