import pytest
from app.main import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health(client):
    """Test endpoint /health       """
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"

def test_scan_no_url(client):
    """Test /scan sans URL renvoie 400"""
    response = client.post("/scan", json={})
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data

def test_scan_with_url(client, monkeypatch):
    """Test /scan avec URL valide (mocké)"""
    def mock_scan(self, url, params=None):
        return {"url": url, "vulnerabilities": [], "severity": "LOW"}
    
    # Remplace scan par le mock
    from app.scanner import APISecurityScanner
    monkeypatch.setattr(APISecurityScanner, "scan", mock_scan)

    response = client.post("/scan", json={"url": "http://example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["url"] == "http://example.com"
    assert data["severity"] == "LOW"
