from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    id: str
    title: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str      # HIGH, MEDIUM, LOW
    category: str
    owasp_mapping: str
    url: str
    evidence: str
    description: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "owasp_mapping": self.owasp_mapping,
            "url": self.url,
            "evidence": self.evidence,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references
        }
