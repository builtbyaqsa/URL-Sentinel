from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_read_root():
    response = client.get('/')
    assert response.status_code == 200

def test_scan_url():
    response = client.post('/scan', json={'url': 'http://192.168.1.1/login-verify'})
    assert response.status_code == 200
    assert 'prediction' in response.json()

def test_get_scans_history():
    response = client.get('/scans')
    assert response.status_code == 200
    assert 'scans' in response.json()
