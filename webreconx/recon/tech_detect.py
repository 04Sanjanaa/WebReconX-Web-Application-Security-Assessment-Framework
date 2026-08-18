import re
import logging
from typing import Dict, Set

logger = logging.getLogger("webreconx.recon.tech_detect")

class TechDetector:
    def __init__(self):
        # Compiled regexes for efficiency
        self.wp_meta_re = re.compile(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress[^"\']*["\']', re.IGNORECASE)
        self.wp_path_re = re.compile(r'/wp-(?:content|includes|admin)/', re.IGNORECASE)
        
        self.jquery_re = re.compile(r'jquery(?:\.min)?\.js', re.IGNORECASE)
        self.react_re = re.compile(r'react(?:\.production|\.development)?(?:\.min)?\.js|id=["\'](?:react-root|app)["\']', re.IGNORECASE)
        self.bootstrap_re = re.compile(r'bootstrap(?:\.min)?\.(?:css|js)', re.IGNORECASE)

    def detect(self, url: str, headers: Dict[str, str], body: str) -> Set[str]:
        """
        Passively identifies technologies from URL, headers, and body content.
        """
        detected: Set[str] = set()
        
        # Normalize header keys to lowercase
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # 1. Header checks
        server_header = headers_lower.get("server", "")
        powered_by = headers_lower.get("x-powered-by", "")

        # Apache detection
        if "apache" in server_header or "apache" in powered_by:
            detected.add("Apache")

        # Nginx detection
        if "nginx" in server_header or "nginx" in powered_by:
            detected.add("Nginx")

        # Flask / Werkzeug detection
        if "werkzeug" in server_header or "flask" in powered_by or "werkzeug" in powered_by:
            detected.add("Flask")

        # Django detection
        if "wsgiserver" in server_header or "django" in powered_by:
            detected.add("Django")

        # 2. HTML Body Analysis
        if body:
            # WordPress detection
            if (self.wp_meta_re.search(body) or 
                self.wp_path_re.search(body) or 
                "wp-submit" in body):
                detected.add("WordPress")

            # jQuery detection
            if self.jquery_re.search(body) or "jQuery" in body:
                detected.add("jQuery")

            # React detection
            if self.react_re.search(body) or "__REACT_DEVTOOLS_GLOBAL_HOOK__" in body:
                detected.add("React")

            # Bootstrap detection
            if self.bootstrap_re.search(body):
                detected.add("Bootstrap")

            # Django-specific indicator: csrfmiddlewaretoken
            if "csrfmiddlewaretoken" in body or "django-debug-toolbar" in body:
                detected.add("Django")

            # Flask-specific error/debug indicators
            if "Werkzeug Debugger" in body or "console.wsgi" in body:
                detected.add("Flask")

        logger.debug(f"Detected technologies for {url}: {detected}")
        return detected
