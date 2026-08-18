from webreconx.core.finding import Finding
from webreconx.scoring.scorer import RiskScorer

def test_single_finding_scoring():
    scorer = RiskScorer()
    
    # 1. High Severity / High Confidence finding
    f_high = Finding(
        id="TEST-1", title="Test High", severity="HIGH", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    assert scorer.calculate_finding_score(f_high) == 7.5

    # 2. Medium Severity / Medium Confidence finding (4.5 * 0.75 = 3.375)
    f_med = Finding(
        id="TEST-2", title="Test Medium", severity="MEDIUM", confidence="MEDIUM",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    assert scorer.calculate_finding_score(f_med) == 3.375

def test_overall_risk_scoring():
    scorer = RiskScorer()
    
    # 1. No findings
    score, level = scorer.calculate_overall_risk([])
    assert score == 0.0
    assert level == "INFO"

    # 2. Single High/High finding
    f1 = Finding(
        id="TEST-1", title="Test High", severity="HIGH", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    score, level = scorer.calculate_overall_risk([f1])
    assert score == 7.5
    assert level == "HIGH"

    # 3. Peak+Accumulation with multiple findings
    # Findings: HIGH/HIGH (7.5) and LOW/HIGH (1.5)
    # Expected overall = 7.5 + (1.5 * 0.1) = 7.65 -> rounded to 7.7
    f2 = Finding(
        id="TEST-2", title="Test Low", severity="LOW", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    score, level = scorer.calculate_overall_risk([f1, f2])
    assert score == 7.7
    assert level == "HIGH"

def test_info_finding_only():
    scorer = RiskScorer()
    f = Finding(
        id="TEST-I", title="Test Info", severity="INFO", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    score, level = scorer.calculate_overall_risk([f])
    assert score == 0.0
    assert level == "INFO"

def test_low_finding_only():
    scorer = RiskScorer()
    f = Finding(
        id="TEST-L", title="Test Low", severity="LOW", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    score, level = scorer.calculate_overall_risk([f])
    assert score == 1.5
    assert level == "LOW"

def test_multiple_medium_findings():
    scorer = RiskScorer()
    f1 = Finding(
        id="TEST-M1", title="Test Med 1", severity="MEDIUM", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    f2 = Finding(
        id="TEST-M2", title="Test Med 2", severity="MEDIUM", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    score, level = scorer.calculate_overall_risk([f1, f2])
    assert score == 5.0
    assert level == "MEDIUM"

def test_max_score_capping():
    scorer = RiskScorer()
    f_crit = Finding(
        id="TEST-C", title="Test Critical", severity="CRITICAL", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    f_high = Finding(
        id="TEST-H", title="Test High", severity="HIGH", confidence="HIGH",
        category="Test", owasp_mapping="A05:2021", url="http://test.com",
        evidence="", description="", impact="", remediation=""
    )
    score, level = scorer.calculate_overall_risk([f_crit, f_high])
    assert score == 10.0
    assert level == "CRITICAL"
