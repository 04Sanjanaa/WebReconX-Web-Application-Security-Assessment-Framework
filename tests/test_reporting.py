import os
import json
import csv
import tempfile
from webreconx.core.finding import Finding
from webreconx.reporting.reporter import ScanReporter

def test_report_generation():
    # Setup mock scan data
    mock_finding = Finding(
        id="SEC-HDR-CSP",
        title="Missing Content-Security-Policy (CSP) Header",
        severity="HIGH",
        confidence="HIGH",
        category="Security Headers",
        owasp_mapping="A05:2021-Security Misconfiguration",
        url="http://example.com/",
        evidence="No CSP header",
        description="CSP description",
        impact="CSP impact",
        remediation="CSP remediation",
        references=["http://ref1.com"]
    )
    
    scan_data = {
        "scan_id": "test-uuid-12345",
        "target": "http://example.com/",
        "scan_mode": "PASSIVE",
        "scanner_version": "1.0.0",
        "start_time": "2026-08-17 12:00:00",
        "end_time": "2026-08-17 12:00:02",
        "duration_seconds": 2.0,
        "pages_discovered": 1,
        "pages_scanned": 1,
        "risk_score": 7.5,
        "risk_level": "HIGH",
        "severity_distribution": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "recon_summary": {
            "detected_technologies": ["Nginx"],
            "robots_txt": {"exists": False, "url": "http://example.com/robots.txt", "disallowed_paths": []},
            "sitemap_xml": {"exists": False, "url": "http://example.com/sitemap.xml", "urls_count": 0}
        },
        "findings": [mock_finding]
    }

    reporter = ScanReporter(scan_data)

    # Use a temporary directory to save output reports
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "scan.json")
        csv_path = os.path.join(tmpdir, "scan.csv")
        html_path = os.path.join(tmpdir, "scan.html")

        # 1. Test JSON report
        reporter.to_json(json_path)
        assert os.path.exists(json_path)
        with open(json_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            assert loaded["scan_id"] == "test-uuid-12345"
            assert loaded["findings"][0]["id"] == "SEC-HDR-CSP"

        # 2. Test CSV report
        reporter.to_csv(csv_path)
        assert os.path.exists(csv_path)
        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
            assert rows[0][0] == "id"
            assert rows[1][0] == "SEC-HDR-CSP"

        # 3. Test HTML report
        reporter.to_html(html_path)
        assert os.path.exists(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
            assert "WebReconX" in html_content
            assert "test-uuid-12345" in html_content
            assert "SEC-HDR-CSP" in html_content
            assert "Nginx" in html_content
