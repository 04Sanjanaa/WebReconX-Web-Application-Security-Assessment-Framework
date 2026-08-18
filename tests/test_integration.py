import threading
import time
import requests
import pytest
from webreconx.testlab.app import app
from webreconx.core.engine import ScanEngine

@pytest.fixture(scope="module")
def flask_server():
    # Start the Flask app in a background thread on an unusual port to avoid collisions
    server_thread = threading.Thread(
        target=lambda: app.run(host='127.0.0.1', port=5099, debug=False, use_reloader=False)
    )
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for the Flask server to initialize
    for _ in range(10):
        try:
            res = requests.get("http://127.0.0.1:5099/", timeout=1.0)
            if res.status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(0.2)
        
    yield "http://127.0.0.1:5099"

def test_integration_lab_scan(flask_server):
    engine = ScanEngine(mode="lab", max_depth=2, max_pages=15)
    report = engine.run_scan(flask_server)
    
    findings = report["findings"]
    finding_ids = [f.id for f in findings]

    # Verify that the test lab vulnerabilities were successfully detected
    assert "SEC-HDR-CSP" in finding_ids          # Missing CSP on /
    assert "COOKIE-NO-HTTPONLY" in finding_ids   # Insecure cookie flags on /insecure-cookies
    assert "COOKIE-NO-SECURE" in finding_ids     # Insecure cookie flags on /insecure-cookies
    assert "DIR-LIST-EXPOSED" in finding_ids     # Directory layout on /directory-listing
    assert "INFO-DISC-SERVER" in finding_ids     # Banner details on /info-disclosure
    
    # Verify that lab mode sensitive file checks were executed
    assert "SENSITIVE-ENV" in finding_ids        # Found simulated /.env
    assert "SENSITIVE-GIT" in finding_ids        # Found simulated /.git/config

    # Verify overall risk calculations are functioning
    assert report["risk_score"] > 0
    assert report["risk_level"] in ("HIGH", "CRITICAL")
    assert report["pages_scanned"] > 1

def test_integration_passive_mode_sensitive_exclusion(flask_server):
    # Running in passive mode against localhost should NOT check/find sensitive files
    engine = ScanEngine(mode="passive", max_depth=2, max_pages=15)
    report = engine.run_scan(flask_server)
    
    findings = report["findings"]
    finding_ids = [f.id for f in findings]

    # Passive mode must NOT contain sensitive files or lab-only findings
    assert "SENSITIVE-ENV" not in finding_ids
    assert "SENSITIVE-GIT" not in finding_ids
    assert "SENSITIVE-BACKUP-ZIP" not in finding_ids
    assert "SENSITIVE-CONFIG-BAK" not in finding_ids

    # But standard passive findings (headers, cookies) should still be found
    assert "SEC-HDR-CSP" in finding_ids

def test_sensitive_paths_blocked_on_public_targets():
    # If the target is public (e.g. google.com), lab mode must reject it early
    engine = ScanEngine(mode="lab")
    with pytest.raises(ValueError):
        engine.run_scan("https://google.com")

    # In passive mode, sensitive path checks are disabled by default
    engine_passive = ScanEngine(mode="passive", authorized_sensitive_checks=False)
    from unittest.mock import patch, MagicMock
    with patch('requests.get') as mock_get:
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.headers = {"Content-Type": "text/html"}
        mock_res.content = b"<html><body>No secrets</body></html>"
        mock_res.text = "<html><body>No secrets</body></html>"
        mock_res.apparent_encoding = "utf-8"
        mock_get.return_value = mock_res
        
        report = engine_passive.run_scan("http://example.com")
        findings = report["findings"]
        finding_ids = [f.id for f in findings]
        
        assert "SENSITIVE-ENV" not in finding_ids
        
        # Verify that /.env was never requested
        for call in mock_get.call_args_list:
            args, kwargs = call
            url_called = args[0]
            assert "/.env" not in url_called
