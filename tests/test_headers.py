from webreconx.checks.headers import HeaderSecurityCheck

def test_missing_headers():
    checker = HeaderSecurityCheck()
    
    # 1. Complete missing headers on HTTPS
    findings = checker.run("https://example.com/", {}, "")
    finding_ids = [f.id for f in findings]
    
    assert "SEC-HDR-CSP" in finding_ids
    assert "SEC-HDR-HSTS" in finding_ids
    assert "SEC-HDR-XFO" in finding_ids
    assert "SEC-HDR-XCTO" in finding_ids
    assert "SEC-HDR-REF" in finding_ids
    assert "SEC-HDR-PERM" in finding_ids
    assert len(findings) == 6

def test_missing_hsts_on_http():
    checker = HeaderSecurityCheck()
    
    # 2. HTTP target should NOT trigger HSTS missing finding
    findings = checker.run("http://example.com/", {}, "")
    finding_ids = [f.id for f in findings]
    
    assert "SEC-HDR-HSTS" not in finding_ids
    assert "SEC-HDR-CSP" in finding_ids
    assert len(findings) == 5

def test_securely_configured_headers():
    checker = HeaderSecurityCheck()
    
    secure_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()"
    }
    
    findings = checker.run("https://example.com/", secure_headers, "")
    assert len(findings) == 0
