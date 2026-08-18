# WebReconX Risk Scoring Methodology

WebReconX implements a transparent, deterministic risk scoring engine in `webreconx/scoring/scorer.py`. The framework uses a **Peak + Accumulation Model** rather than a simple arithmetic average. This ensures that the overall risk rating is dominated by the most severe finding, while still accounting for the cumulative impact of multiple minor vulnerabilities.

---

## 1. Mathematical Scoring Formula

### Finding-Level Score
For any individual finding \(f\), its score is:
\[
\text{Score}(f) = \text{Severity Weight} \times \text{Confidence Weight}
\]

#### Severity Weights
- **CRITICAL**: 9.5
- **HIGH**: 7.5
- **MEDIUM**: 4.5
- **LOW**: 1.5
- **INFO**: 0.0

#### Confidence Weights
- **HIGH**: 1.0
- **MEDIUM**: 0.75
- **LOW**: 0.50

---

### Overall Risk Score
The overall **Risk Score** for the base target URL is:
\[
\text{Risk Score} = \min\left(10.0, \, \text{Peak Score} + \left( \sum_{i=1}^{N-1} \text{Score}(f_{i}) \times 0.1 \right)\right)
\]
Where:
- \(\text{Peak Score}\) is the maximum finding score found on the target (\(\text{Score}(f_0)\)).
- \(\sum \text{Score}(f_{i})\) is the sum of scores for all *other* findings \(f_1, f_2, \dots, f_{N-1}\) (excluding the peak).
- Capped at a maximum of **10.0** and rounded to 1 decimal place.

#### Risk Scale Meaning
- **0.0** = Minimal detected risk (no vulnerability findings, or info-only findings).
- **10.0** = Maximum detected risk (critical configuration exposures or highly severe combined findings).

#### Risk Rating Mapping
- **CRITICAL**: 9.0 – 10.0
- **HIGH**: 7.0 – 8.9
- **MEDIUM**: 4.0 – 6.9
- **LOW**: 0.1 – 3.9
- **INFO**: 0.0

---

## 2. Worked Examples

### Example A: A scan identifies three findings:
1. **Missing Content Security Policy**: Severity: **HIGH** (7.5), Confidence: **HIGH** (1.0).
   - Finding Score: \(7.5 \times 1.0 = 7.5\)
2. **Missing Referrer-Policy**: Severity: **LOW** (1.5), Confidence: **HIGH** (1.0).
   - Finding Score: \(1.5 \times 1.0 = 1.5\)
3. **Server Banner Exposed**: Severity: **INFO** (0.0), Confidence: **HIGH** (1.0).
   - Finding Score: \(0.0 \times 1.0 = 0.0\)

**Calculations:**
- Sort scores: `[7.5, 1.5, 0.0]`
- Peak Score: `7.5`
- Other Scores Sum: `1.5 + 0.0 = 1.5`
- Raw Overall Score: \(7.5 + (1.5 \times 0.1) = 7.5 + 0.15 = 7.65\)
- Normalized & Rounded Score: **7.7**
- **Risk Level**: **HIGH**

---

### Example B: Local Lab scan with critical exposure:
1. **Exposed .env configuration**: Severity: **CRITICAL** (9.5), Confidence: **HIGH** (1.0).
   - Finding Score: \(9.5 \times 1.0 = 9.5\)
2. **Missing CSP**: Severity: **HIGH** (7.5), Confidence: **HIGH** (1.0).
   - Finding Score: \(7.5 \times 1.0 = 7.5\)
3. **Insecure Cookie**: Severity: **MEDIUM** (4.5), Confidence: **HIGH** (1.0).
   - Finding Score: \(4.5 \times 1.0 = 4.5\)

**Calculations:**
- Sort scores: `[9.5, 7.5, 4.5]`
- Peak Score: `9.5`
- Other Scores Sum: `7.5 + 4.5 = 12.0`
- Raw Overall Score: \(9.5 + (12.0 \times 0.1) = 9.5 + 1.2 = 10.7\)
- Normalized & Capped Score: **10.0**
- **Risk Level**: **CRITICAL**

---

### Example C: A secure target scan (or no vulnerabilities):
If the scanner identifies no vulnerabilities, or only info-level banner disclosures (e.g. `Server: nginx` which has a severity weight of 0.0).

1. **Server Header Disclosed**: Severity: **INFO** (0.0), Confidence: **HIGH** (1.0).
   - Finding Score: \(0.0 \times 1.0 = 0.0\)

**Calculations:**
- Peak Score: `0.0`
- Other Scores Sum: `0.0`
- Raw Overall Score: \(0.0 + (0.0 \times 0.1) = 0.0\)
- Normalized & Capped Score: **0.0**
- **Risk Level**: **INFO** (Minimal detected risk)
