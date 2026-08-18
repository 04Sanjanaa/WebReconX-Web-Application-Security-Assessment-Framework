from webreconx.checks.cookies import CookieSecurityCheck

def test_insecure_cookies():
    checker = CookieSecurityCheck()
    
    # Simulates requests merged Set-Cookie string for multiple insecure cookies
    headers = {
        "Set-Cookie": "session_id=123; Path=/, preferences=dark; Path=/; SameSite=None"
    }
    
    findings = checker.run("https://example.com/", headers, "")
    finding_ids = [f.id for f in findings]
    
    # session_id cookie is missing httponly, secure, samesite
    assert findings[0].title == "Cookie 'session_id' Missing 'HttpOnly' Attribute"
    assert findings[1].title == "Cookie 'session_id' Missing 'Secure' Attribute"
    assert findings[2].title == "Cookie 'session_id' Insecure 'SameSite' Configuration"
    
    # preferences cookie is missing httponly, secure, and has SameSite=None
    assert "COOKIE-NO-HTTPONLY" in finding_ids
    assert "COOKIE-NO-SECURE" in finding_ids
    assert "COOKIE-NO-SAMESITE" in finding_ids

def test_secure_cookies():
    checker = CookieSecurityCheck()
    
    headers = {
        "Set-Cookie": "secure_session=456; Path=/; HttpOnly; Secure; SameSite=Lax"
    }
    
    findings = checker.run("https://example.com/", headers, "")
    assert len(findings) == 0

def test_cookie_individual_flags():
    checker = CookieSecurityCheck()
    
    # Cookie 1: Only HttpOnly missing
    headers_1 = {"Set-Cookie": "cookie1=val1; Secure; SameSite=Lax"}
    findings_1 = checker.run("https://example.com/", headers_1, "")
    assert len(findings_1) == 1
    assert findings_1[0].id == "COOKIE-NO-HTTPONLY"

    # Cookie 2: Only Secure missing
    headers_2 = {"Set-Cookie": "cookie2=val2; HttpOnly; SameSite=Strict"}
    findings_2 = checker.run("https://example.com/", headers_2, "")
    assert len(findings_2) == 1
    assert findings_2[0].id == "COOKIE-NO-SECURE"

    # Cookie 3: Only SameSite missing
    headers_3 = {"Set-Cookie": "cookie3=val3; HttpOnly; Secure"}
    findings_3 = checker.run("https://example.com/", headers_3, "")
    assert len(findings_3) == 1
    assert findings_3[0].id == "COOKIE-NO-SAMESITE"
