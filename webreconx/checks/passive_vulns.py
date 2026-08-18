import logging
import re
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Dict
from webreconx.checks.base import BaseCheck
from webreconx.core.finding import Finding
from webreconx.core.validator import TargetValidator

logger = logging.getLogger("webreconx.checks.passive_vulns")

class PassiveVulnsCheck(BaseCheck):
    def __init__(self, base_url: str = "", authorized_sensitive_checks: bool = False):
        super().__init__()
        self.base_url = base_url
        self.authorized_sensitive_checks = authorized_sensitive_checks
        self.sensitive_checks_run = False  # Ensure we only run sensitive checks once per base URL

    def run(self, url: str, headers: Dict[str, str], body: str, mode: str = "passive") -> List[Finding]:
        findings: List[Finding] = []
        
        # 1. Insecure HTTP Usage
        if url.lower().startswith("http://"):
            findings.append(Finding(
                id="INSECURE-HTTP",
                title="Insecure HTTP Protocol Usage",
                severity="MEDIUM",
                confidence="HIGH",
                category="Insecure Transport",
                owasp_mapping="A02:2021-Cryptographic Failures",
                url=url,
                evidence=f"Protocol scheme is HTTP: {url}",
                description="The site uses the unencrypted HTTP protocol instead of HTTPS. All data transmitted between the client and server is sent in cleartext.",
                impact="Attackers on the same network (e.g. public Wi-Fi) can sniff login credentials, session cookies, and sensitive user data, or inject malicious scripts into the traffic (Man-in-the-Middle).",
                remediation="Configure the server to redirect all HTTP traffic to HTTPS and use TLS/SSL certificates.",
                references=["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures", "https://developer.mozilla.org/en-US/docs/Glossary/HTTPS"]
            ))

        # Normalize header keys for case insensitivity
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # 2. Server Information Disclosure
        server_header = headers_lower.get("server", "")
        if server_header:
            # Check if it discloses version details (e.g., Apache/2.4.41 or nginx/1.18.0)
            import re
            # Matches strings containing numbers separated by dots or dashes, like Apache/2.4.41
            has_version = bool(re.search(r'/\d+(\.\d+)*', server_header))
            
            if has_version:
                findings.append(Finding(
                    id="INFO-DISC-SERVER",
                    title="Detailed Server Version Disclosure",
                    severity="LOW",
                    confidence="HIGH",
                    category="Information Disclosure",
                    owasp_mapping="A05:2021-Security Misconfiguration",
                    url=url,
                    evidence=f"Server: {server_header}",
                    description="The server response header discloses detailed product names and version numbers.",
                    impact="Attackers can use specific server version details to look up known CVEs and coordinate targeted exploits.",
                    remediation="Configure the web server to restrict version information (e.g., set ServerTokens ProductOnly in Apache or server_tokens off in nginx).",
                    references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"]
                ))
            else:
                # Basic server header disclosure
                findings.append(Finding(
                    id="INFO-DISC-SERVER-GEN",
                    title="Server Header Disclosed",
                    severity="INFO",
                    confidence="HIGH",
                    category="Information Disclosure",
                    owasp_mapping="Informational / No direct OWASP Top 10 mapping",
                    url=url,
                    evidence=f"Server: {server_header}",
                    description="The web server banner is exposed in the HTTP headers.",
                    impact="Discloses the general web server software family (e.g. nginx, Apache, Werkzeug). Not critical, but increases information footprint.",
                    remediation="If possible, remove or obfuscate the Server header completely.",
                    references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"]
                ))

        # 3. X-Powered-By Banner
        powered_by = headers_lower.get("x-powered-by", "")
        if powered_by:
            findings.append(Finding(
                id="INFO-DISC-POWERED",
                title="X-Powered-By Header Information Disclosure",
                severity="LOW",
                confidence="HIGH",
                category="Information Disclosure",
                owasp_mapping="A05:2021-Security Misconfiguration",
                url=url,
                evidence=f"X-Powered-By: {powered_by}",
                description="The X-Powered-By header is present, revealing specific backend technologies (e.g. PHP/7.4, Express, Flask).",
                impact="Discloses technology stack specifics, easing target fingerprinting for attackers.",
                remediation="Disable or remove the X-Powered-By header from application config/web server configuration.",
                references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"]
            ))

        # 4. Exposed Directory Listing Indicator
        # Check if page is directory listing
        title_lower = ""
        # Inspect HTML content type
        if "text/html" in headers_lower.get("content-type", ""):
            # We can check body for directory list structures
            body_lower = body.lower()
            if "index of /" in body_lower or "directory listing for" in body_lower or "parent directory" in body_lower:
                # Double check with title
                findings.append(Finding(
                    id="DIR-LIST-EXPOSED",
                    title="Exposed Directory Listing Layout",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="Information Disclosure",
                    owasp_mapping="A01:2021-Broken Access Control",
                    url=url,
                    evidence="Common directory indexing text (e.g. 'Index of /' or 'Directory listing') found in body.",
                    description="The web server lists folder contents when no index file is present, exposing files to public viewing.",
                    impact="Sensitive files, backups, logs, or source code inside the directory can be accessed and downloaded by unauthorized parties.",
                    remediation="Disable directory browsing. In Nginx, set 'autoindex off;'. In Apache, remove 'Indexes' option.",
                    references=["https://owasp.org/www-community/Directory_Restriction"]
                ))

        # 5. Sensitive Path Checks (only executed once at base URL)
        # Check if the URL is the base target and we haven't run sensitive checks yet
        is_base = (url.rstrip('/') == self.base_url.rstrip('/'))
        
        # Determine if sensitive checks are permitted
        # Only allowed in Lab mode with localhost, OR if user explicitly opted in using authorized checks flag
        validator = TargetValidator(mode=mode)
        is_target_local = validator.is_localhost(url)
        
        allowed_to_run_sensitive = False
        if mode == "lab" and is_target_local:
            allowed_to_run_sensitive = True
        elif self.authorized_sensitive_checks:
            # Safe safeguard: if authorized_sensitive_checks is true, allow scanning public target but log warning
            allowed_to_run_sensitive = True

        if is_base and allowed_to_run_sensitive and not self.sensitive_checks_run:
            self.sensitive_checks_run = True
            findings.extend(self._run_sensitive_path_checks(url))

        return findings

    def _run_sensitive_path_checks(self, base_url: str) -> List[Finding]:
        findings: List[Finding] = []
        
        # Direct paths to test relative to base URL
        paths_to_test = {
            "/.env": {
                "id": "SENSITIVE-ENV",
                "title": "Exposed Environment Configuration File (.env)",
                "severity": "CRITICAL",
                "owasp_mapping": "A05:2021-Security Misconfiguration",
                "checks": [r"(?i)DB_HOST", r"(?i)SECRET_KEY", r"(?i)PASSWORD"],
                "desc": "An exposed .env file containing environment variables was detected at the root.",
                "impact": "Exposes highly critical database credentials, private API keys, secret hashing tokens, and configuration details.",
                "remed": "Restrict access to .env files in server config or store environment variables outside the web document root."
            },
            "/.git/config": {
                "id": "SENSITIVE-GIT",
                "title": "Exposed Git Repository Configuration",
                "severity": "HIGH",
                "owasp_mapping": "A05:2021-Security Misconfiguration",
                "checks": [r"(?i)\[core\]", r"(?i)repositoryformatversion"],
                "desc": "An exposed Git configuration file was found, suggesting the /.git directory is public.",
                "impact": "Allows attackers to reconstruct the entire source code repository, exposing secrets and code vulnerabilities.",
                "remed": "Configure the web server to block access to the /.git folder."
            },
            "/backup.zip": {
                "id": "SENSITIVE-BACKUP-ZIP",
                "title": "Exposed Backup Archive File (backup.zip)",
                "severity": "MEDIUM",
                "owasp_mapping": "A05:2021-Security Misconfiguration",
                "checks": [],  # Checks size & headers
                "desc": "An archive backup file named 'backup.zip' is publicly downloadable.",
                "impact": "May contain source code, database dumps, configuration keys, or other developer backups.",
                "remed": "Remove public backup files immediately and configure automated backups outside of the public root directory."
            },
            "/config.php.bak": {
                "id": "SENSITIVE-CONFIG-BAK",
                "title": "Exposed Backup Configuration File (config.php.bak)",
                "severity": "HIGH",
                "owasp_mapping": "A05:2021-Security Misconfiguration",
                "checks": [r"(?i)<\?php", r"(?i)define", r"(?i)db_"],
                "desc": "A backup PHP config file was found, which might be rendered as plaintext by the server.",
                "impact": "Plaintext files bypass PHP compilation, exposing raw database connection passwords and configuration strings.",
                "remed": "Ensure backup/temporary files are deleted, or block access to *.bak extension files."
            }
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) WebReconX/1.0.0'
        }

        for path, info in paths_to_test.items():
            test_url = urljoin(base_url, path)
            logger.info(f"Checking sensitive path: {test_url}")
            try:
                # Use a small timeout, do not follow redirects
                res = requests.get(test_url, headers=headers, timeout=3.0, allow_redirects=False)
                if res.status_code == 200:
                    content = res.text
                    content_type = res.headers.get("Content-Type", "")
                    
                    matched = True
                    # If regex patterns are defined, check for matches in response
                    if info["checks"]:
                        matched = any(re.search(pat, content) for pat in info["checks"])
                    else:
                        # For binary files like backup.zip, check content-type or size
                        if path == "/backup.zip":
                            matched = ("zip" in content_type.lower() or 
                                       "octet-stream" in content_type.lower() or 
                                       len(res.content) > 100)
                    
                    if matched:
                        findings.append(Finding(
                            id=info["id"],
                            title=info["title"],
                            severity=info["severity"],
                            confidence="HIGH",
                            category="Sensitive Information Disclosure",
                            owasp_mapping=info["owasp_mapping"],
                            url=test_url,
                            evidence=f"HTTP 200 OK. Content-Type: {content_type}. Content snippet: {content[:100].strip()}",
                            description=info["desc"],
                            impact=info["impact"],
                            remediation=info["remed"],
                            references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"]
                        ))
            except requests.RequestException as e:
                logger.warning(f"Error checking sensitive path {test_url}: {e}")

        return findings
