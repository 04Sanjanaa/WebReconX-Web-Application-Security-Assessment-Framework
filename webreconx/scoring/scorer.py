import logging
from typing import List, Dict, Any, Tuple
from webreconx.core.finding import Finding

logger = logging.getLogger("webreconx.scoring")

# Severity Weights
SEVERITY_WEIGHTS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 4.5,
    "LOW": 1.5,
    "INFO": 0.0
}

# Confidence Weights
CONFIDENCE_WEIGHTS = {
    "HIGH": 1.0,
    "MEDIUM": 0.75,
    "LOW": 0.5
}

class RiskScorer:
    def __init__(self):
        pass

    def calculate_finding_score(self, finding: Finding) -> float:
        """Calculates the score of a single finding based on severity and confidence."""
        sev = finding.severity.upper()
        conf = finding.confidence.upper()
        
        s_weight = SEVERITY_WEIGHTS.get(sev, 0.0)
        c_weight = CONFIDENCE_WEIGHTS.get(conf, 1.0)
        
        return s_weight * c_weight

    def calculate_overall_risk(self, findings: List[Finding]) -> Tuple[float, str]:
        """
        Calculates the overall risk score and rating.
        Formula: Peak + Accumulation Model
        - Base score is the maximum single finding score.
        - Adds 10% of the sum of all other finding scores.
        - Capped at 10.0.
        """
        if not findings:
            return 0.0, "INFO"

        finding_scores = [self.calculate_finding_score(f) for f in findings]
        
        # Sort scores in descending order
        finding_scores.sort(reverse=True)
        
        peak_score = finding_scores[0]
        other_scores_sum = sum(finding_scores[1:])
        
        # Calculate score using the formula
        overall_score = peak_score + (other_scores_sum * 0.1)
        
        # Cap at 10.0 and round to 1 decimal place
        overall_score = min(10.0, round(overall_score, 1))
        
        # Map score to risk category
        if overall_score >= 9.0:
            risk_level = "CRITICAL"
        elif overall_score >= 7.0:
            risk_level = "HIGH"
        elif overall_score >= 4.0:
            risk_level = "MEDIUM"
        elif overall_score >= 0.1:
            risk_level = "LOW"
        else:
            risk_level = "INFO"
            
        logger.info(f"Overall Risk Calculated: Score={overall_score}, Level={risk_level}")
        return overall_score, risk_level

    def get_severity_distribution(self, findings: List[Finding]) -> Dict[str, int]:
        """Helper to get count of findings by severity."""
        dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity.upper()
            if sev in dist:
                dist[sev] += 1
        return dist
