from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_read_root():
    response = client.get('/')
    assert response.status_code == 200

def test_scan_url_endpoint():
    response = client.post('/scan', json={'url': 'http://192.168.1.1/login-verify'})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data['prediction'] == 'Malicious'
    assert 'features' in json_data

def test_get_scans_endpoint():
    response = client.get('/scans')
    assert response.status_code == 200
    assert 'scans' in response.json()
