from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_read_root():
    response = client.get('/')
    assert response.status_code == 200

def test_get_scans_endpoint():
    response = client.get('/scans')
    assert response.status_code == 200
    assert 'scans' in response.json()
