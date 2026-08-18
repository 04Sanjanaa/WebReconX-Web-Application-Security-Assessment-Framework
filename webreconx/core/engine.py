import uuid
import time
import datetime
import logging
from typing import Dict, List, Any
from webreconx.core.validator import TargetValidator
from webreconx.crawler.crawler import WebCrawler
from webreconx.recon.gatherer import ReconGatherer
from webreconx.recon.tech_detect import TechDetector
from webreconx.checks.headers import HeaderSecurityCheck
from webreconx.checks.cookies import CookieSecurityCheck
from webreconx.checks.passive_vulns import PassiveVulnsCheck
from webreconx.scoring.scorer import RiskScorer

logger = logging.getLogger("webreconx.core.engine")

class ScanEngine:
    def __init__(self, mode: str = "passive", max_depth: int = 2, max_pages: int = 50, timeout: float = 5.0, authorized_sensitive_checks: bool = False):
        self.mode = mode.lower()
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.authorized_sensitive_checks = authorized_sensitive_checks
        
        self.validator = TargetValidator(mode=self.mode)
        self.scorer = RiskScorer()
        self.tech_detector = TechDetector()

    def run_scan(self, url: str) -> Dict[str, Any]:
        """
        Coordinates the entire security assessment scanning lifecycle.
        """
        scan_id = str(uuid.uuid4())
        start_time_dt = datetime.datetime.now()
        start_time_str = start_time_dt.strftime("%Y-%m-%d %H:%M:%S")
        start_perf = time.perf_counter()

        logger.info(f"Starting scan {scan_id} on {url} in mode {self.mode.upper()}")

        # 1. Target Validation
        try:
            target_url = self.validator.validate_target(url)
        except ValueError as e:
            logger.error(f"Target validation failed: {e}")
            raise

        # 2. Reconnaissance (robots.txt & sitemap.xml)
        recon_gatherer = ReconGatherer(target_url, timeout=self.timeout)
        robots_data = recon_gatherer.fetch_robots_txt()
        sitemap_data = recon_gatherer.fetch_sitemap_xml()

        # 3. Controlled Scoped Crawling
        crawler = WebCrawler(
            base_url=target_url, 
            validator=self.validator, 
            max_depth=self.max_depth, 
            max_pages=self.max_pages, 
            timeout=self.timeout
        )
        crawled_pages = crawler.start()

        # Gather links found to calculate pages discovered vs scanned
        discovered_urls_set = set(crawler.visited_urls)
        for page in crawled_pages.values():
            for link in page.get("links", []):
                discovered_urls_set.add(link)

        # 4. Initialize Checks
        # Pass base target URL and sensitive checks flag to the passive vulnerability suite
        checks = [
            HeaderSecurityCheck(),
            CookieSecurityCheck(),
            PassiveVulnsCheck(
                base_url=target_url, 
                authorized_sensitive_checks=self.authorized_sensitive_checks
            )
        ]

        findings: List[Any] = []
        detected_techs = set()

        # 5. Run Checks and Tech Fingerprinting on each page
        for page_url, page_info in crawled_pages.items():
            headers = page_info.get("headers", {})
            body = page_info.get("body", "")
            
            # Technology fingerprinting
            techs = self.tech_detector.detect(page_url, headers, body)
            detected_techs.update(techs)

            # Vulnerability checks
            for check in checks:
                try:
                    page_findings = check.run(page_url, headers, body, mode=self.mode)
                    findings.extend(page_findings)
                except Exception as e:
                    logger.error(f"Error running check {check.__class__.__name__} on {page_url}: {e}")

        # Deduplicate findings by title and url to avoid duplicates across crawls
        unique_findings = []
        seen_findings = set()
        for f in findings:
            finding_key = (f.id, f.url)
            if finding_key not in seen_findings:
                seen_findings.add(finding_key)
                unique_findings.append(f)

        # 6. Scoring Calculations
        overall_score, overall_risk = self.scorer.calculate_overall_risk(unique_findings)
        severity_dist = self.scorer.get_severity_distribution(unique_findings)

        # 7. Finalize Performance Metrics
        end_time_dt = datetime.datetime.now()
        end_time_str = end_time_dt.strftime("%Y-%m-%d %H:%M:%S")
        duration = round(time.perf_counter() - start_perf, 2)

        # 8. Consolidate Scan Report Metadata
        scan_report = {
            "scan_id": scan_id,
            "target": target_url,
            "scan_mode": self.mode.upper(),
            "scanner_version": "1.0.0",
            "start_time": start_time_str,
            "end_time": end_time_str,
            "duration_seconds": duration,
            "pages_discovered": len(discovered_urls_set),
            "pages_scanned": len(crawled_pages),
            "risk_score": overall_score,
            "risk_level": overall_risk,
            "severity_distribution": severity_dist,
            "recon_summary": {
                "detected_technologies": list(detected_techs),
                "robots_txt": {
                    "exists": robots_data["exists"],
                    "url": robots_data["url"],
                    "disallowed_paths": robots_data["disallowed_paths"]
                },
                "sitemap_xml": {
                    "exists": sitemap_data["exists"],
                    "url": sitemap_data["url"],
                    "urls_count": len(sitemap_data["urls"])
                }
            },
            "findings": unique_findings
        }

        return scan_report
