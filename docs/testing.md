# WebReconX Testing Methodology

To guarantee reliability, accuracy, and safe operations, WebReconX features a comprehensive automated unit and integration test suite using **pytest**. Testing is performed in isolation, utilizing a mock environment and local loopback integration.

## Testing Strategy & Components

The test suite covers:

1. **Target Validation (`test_validator.py`)**:
   - URL schema verification (blocking ftp://, file://, etc.).
   - URL normalization rules (stripping ports, formatting paths, lowercase matching).
   - Localhost restrictions (blocking public ranges in lab mode).
   - Domain boundary scope enforcement.

2. **Web Crawler (`test_crawler.py`)**:
   - Max page limits and max depth boundaries.
   - Prevention of duplicate crawling loops.
   - Redirect scope evaluation (blocking crawling redirects to external targets).

3. **HTTP Header Auditing (`test_headers.py`)**:
   - Confirming appropriate findings are triggered when CSP, HSTS, XFO, XCTO, Referrer-Policy, and Permissions-Policy are missing.
   - Confirming no false-positives are thrown when these headers are properly configured.

4. **Cookie Flag Auditing (`test_cookies.py`)**:
   - Verifying detection of missing `HttpOnly`, `Secure`, and `SameSite` flags.
   - Multi-cookie parsing validation (handling requests-merged Set-Cookie headers containing dates).

5. **Risk Scoring math (`test_scoring.py`)**:
   - Confirming individual findings are weighted correctly.
   - Validating the Peak + Accumulation mathematical formula against known test profiles.

6. **Reporting output (`test_reporting.py`)**:
   - Validating correct JSON structure.
   - Verifying CSV rows formatting.
   - Confirming valid HTML is written and CSS templates are correctly populated.

---

## Running the Automated Tests

Ensure you have installed the requirements:
```bash
pip install -r requirements.txt
```

Run all tests via `pytest`:
```bash
pytest tests/ -v
```

This will run all validation tests in the `tests/` directory. Tests automatically mock web requests using `unittest.mock` or run a local test server context where required, ensuring no external network requests are sent during verification.
