from webreconx.recon.tech_detect import TechDetector

def test_tech_detect_wordpress():
    detector = TechDetector()
    
    # 1. Generator meta tag detection
    body = '<html><head><meta name="generator" content="WordPress 6.2.2"></head></html>'
    techs = detector.detect("http://example.com/", {}, body)
    assert "WordPress" in techs

    # 2. Path directory detection
    body_path = '<html><body><script src="http://example.com/wp-content/themes/twentytwenty/main.js"></script></body></html>'
    techs_path = detector.detect("http://example.com/", {}, body_path)
    assert "WordPress" in techs_path

def test_tech_detect_jquery_bootstrap():
    detector = TechDetector()
    
    # 1. jQuery detection
    body_jq = '<html><body><script src="/js/jquery.min.js"></script></body></html>'
    techs_jq = detector.detect("http://example.com/", {}, body_jq)
    assert "jQuery" in techs_jq

    # 2. Bootstrap detection
    body_bs = '<html><head><link rel="stylesheet" href="/assets/bootstrap.min.css"></head></html>'
    techs_bs = detector.detect("http://example.com/", {}, body_bs)
    assert "Bootstrap" in techs_bs

def test_tech_detect_flask_django():
    detector = TechDetector()
    
    # 1. Flask detection via Server header
    techs_flask = detector.detect("http://example.com/", {"Server": "Werkzeug/2.2.2 Python/3.10"}, "")
    assert "Flask" in techs_flask

    # 2. Django detection via CSRF form input field
    body_dj = '<html><body><input type="hidden" name="csrfmiddlewaretoken" value="abc"></body></html>'
    techs_dj = detector.detect("http://example.com/", {}, body_dj)
    assert "Django" in techs_dj

def test_tech_detect_no_false_positives():
    detector = TechDetector()
    
    # Unrelated body text mentioning react or bootstrap without script imports
    body_clean = '<html><body>I want to learn about react, and styling using bootstrap. There is no jquery here.</body></html>'
    techs_clean = detector.detect("http://example.com/", {"Server": "CustomServer"}, body_clean)
    
    # None of these should be detected from plain body text since they lack import signatures or headers
    assert "React" not in techs_clean
    assert "Bootstrap" not in techs_clean
    assert "jQuery" not in techs_clean
