# WebReconX Architecture Documentation

WebReconX is designed as a modular, extensible, and clean Python security assessment framework. It is structured into clearly separated feature areas to ensure maintainability, testability, and ease of expansion.

## Directory Structure Overview
```
webreconx/
├── __init__.py         # Package exports & version tracking
├── core/
│   ├── validator.py    # URL normalization, domain validation & scope restrictions
│   └── engine.py       # Main orchestrator for scan processes
├── recon/
│   ├── gatherer.py     # robots.txt, sitemap.xml parser
│   └── tech_detect.py  # Passive technology banner/content detector
├── crawler/
│   └── crawler.py      # Scoped, limited, manual redirect-safe web crawler
├── checks/
│   ├── base.py         # Abstraction template for check suites
│   ├── headers.py      # HTTP Response header security auditor
│   ├── cookies.py      # Set-Cookie flags and attributes auditor
│   └── passive_vulns.py# Insecure protocol, banner exposure & directory/sensitive paths checks
├── scoring/
│   └── scorer.py       # Peak+Accumulation vulnerability risk scorer
├── reporting/
│   └── reporter.py     # JSON, CSV, and HTML reporting engine
├── cli/
│   └── cli.py          # Argparse parser and stdout formatter
├── testlab/
│   └── app.py          # Flask vulnerable application for automated test verification
```

## Component Interaction Flow

1. **CLI Initialization**: User runs the CLI (e.g. `python webreconx.py scan --url http://127.0.0.1:5000 --mode lab`). The `cli.py` module parses options, executes validations, and invokes the `ScanEngine`.
2. **Target Validation**: `validator.py` sanitizes the target URL, verifies it is HTTP/HTTPS, evaluates whether it is localhost (enforcing localhost rules if `--mode lab` is specified), and establishes the target scope boundary.
3. **Passive Reconnaissance**: `gatherer.py` attempts to fetch `/robots.txt` and `/sitemap.xml` to parse structure, allowed/disallowed paths, and page lists.
4. **Controlled Crawling**: `crawler.py` initiates crawl. It checks links depth-by-depth. For every redirect, the crawler halts automatic redirects, resolves the location, validates the redirected URL against the target scope, and only processes it if it remains in-scope.
5. **Technology & Vulnerability Checks**:
   - `tech_detect.py` performs passive analysis on headers and body pages to find Nginx, Apache, WordPress, React, jQuery, Flask, Django, and Bootstrap.
   - The engine iterates through the check suite (headers, cookies, passive vulnerabilities) for all visited pages.
   - **Sensitive path checking** (`/.git/config`, `/.env`, etc.) is triggered *only* against the base target URL, and *only* if the target resolves to localhost under `--mode lab` or if the user explicitly provided `--authorized-sensitive-checks`.
6. **Risk Scoring**: `scorer.py` compiles findings, calculates individual vulnerability scores based on severity and confidence weights, and applies the Peak+Accumulation formula to output a final score (0.0 to 10.0) and a risk rating.
7. **Report Generation**: `reporter.py` aggregates scan metadata, crawler metrics, and findings list, exporting results into JSON, CSV, and a single-page HTML report.
