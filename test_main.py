import pytest
from fastapi.testclient import TestClient
from app import app
from database import Base, engine

# Initialize database schema before running tests
Base.metadata.create_all(bind=engine)

client = TestClient(app)

def test_read_root():
    response = client.get('/')
    assert response.status_code == 200
    assert response.json() == {'message': 'URL-Sentinel API is running'}

def test_scan_url_endpoint():
    response = client.post('/scan', json={'url': 'http://192.168.1.1/login-verify'})
    assert response.status_code == 200
    json_data = response.json()
    assert 'prediction' in json_data
    assert json_data['prediction'] == 'Malicious'

def test_get_scans_history():
    response = client.get('/scans')
    assert response.status_code == 200
    assert 'scans' in response.json()