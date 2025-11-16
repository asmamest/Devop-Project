import pytest
from unittest.mock import patch, MagicMock
from app.scanner import APISecurityScanner

@pytest.fixture
def scanner():
    return APISecurityScanner()

# ----------------------
# Tests pour _calculate_severity
# ----------------------
def test_calculate_severity_low(scanner):
    result = scanner._calculate_severity([])
    assert result == "LOW"

def test_calculate_severity_high(scanner):
    vulns = [{"type": "SQL Injection"}, {"type": "Missing Security Headers"}]
    result = scanner._calculate_severity(vulns)
    assert result == "HIGH"

def test_calculate_severity_medium(scanner):
    vulns = [{"type": "Missing Security Headers"}]
    result = scanner._calculate_severity(vulns)
    assert result == "MEDIUM"

# ----------------------
# Tests pour check_sql_injection
# ----------------------
@patch("app.scanner.requests.get")
def test_check_sql_injection_vulnerable(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.text = "MySQL syntax error"
    mock_get.return_value = mock_resp

    params = {"username": "admin"}
    result = scanner.check_sql_injection("http://example.com", params)
    assert result["vulnerable"] is True
    assert result["type"] == "SQL Injection"

@patch("app.scanner.requests.get")
def test_check_sql_injection_safe(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.text = "All good"
    mock_get.return_value = mock_resp

    params = {"username": "admin"}
    result = scanner.check_sql_injection("http://example.com", params)
    assert result["vulnerable"] is False

# ----------------------
# Tests pour check_xss
# ----------------------
@patch("app.scanner.requests.get")
def test_check_xss_vulnerable(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.text = "<script>alert('XSS')</script>"
    mock_get.return_value = mock_resp

    params = {"q": "test"}
    result = scanner.check_xss("http://example.com", params)
    assert result["vulnerable"] is True
    assert result["type"] == "XSS"

@patch("app.scanner.requests.get")
def test_check_xss_safe(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.text = "No XSS here"
    mock_get.return_value = mock_resp

    params = {"q": "test"}
    result = scanner.check_xss("http://example.com", params)
    assert result["vulnerable"] is False

# ----------------------
# Tests pour check_headers
# ----------------------
@patch("app.scanner.requests.get")
def test_check_headers_missing(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.headers = {}  # aucun header
    mock_get.return_value = mock_resp

    result = scanner.check_headers("http://example.com")
    assert "X-Content-Type-Options" in result["missing_headers"]

@patch("app.scanner.requests.get")
def test_check_headers_present(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Strict-Transport-Security': 'max-age=31536000',
        'Content-Security-Policy': "default-src 'self'"
    }
    mock_get.return_value = mock_resp

    result = scanner.check_headers("http://example.com")
    assert result["missing_headers"] == []

# ----------------------
# Tests pour check_sensitive_info
# ----------------------
@patch("app.scanner.requests.get")
def test_check_sensitive_info_found(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.text = 'api_key="12345" password="secret" token="abc"'
    mock_get.return_value = mock_resp

    result = scanner.check_sensitive_info("http://example.com")
    assert len(result) == 3
    types = [r["type"] for r in result]
    assert "api_key" in types and "password" in types and "token" in types

@patch("app.scanner.requests.get")
def test_check_sensitive_info_none(mock_get, scanner):
    mock_resp = MagicMock()
    mock_resp.text = 'No sensitive info here'
    mock_get.return_value = mock_resp

    result = scanner.check_sensitive_info("http://example.com")
    assert result == []

# ----------------------
# Tests pour scan complet
# ----------------------
@patch("app.scanner.requests.get")
def test_scan_full(mock_get, scanner):
    # Response générique pour tous les checks
    mock_resp = MagicMock()
    mock_resp.text = "All good"
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    result = scanner.scan("http://example.com", {"param": "test"})
    assert result["url"] == "http://example.com"
    assert "vulnerabilities" in result
    assert result["severity"] in ["LOW", "MEDIUM", "HIGH"]
    assert "scan_id" in result
