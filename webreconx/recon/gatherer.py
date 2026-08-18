import logging
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urlunparse
from typing import Dict, List, Any, Optional

logger = logging.getLogger("webreconx.recon")

class ReconGatherer:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url
        self.timeout = timeout
        
        # Calculate target root for robots.txt/sitemap.xml checks
        parsed = urlparse(base_url)
        self.root_url = f"{parsed.scheme}://{parsed.netloc}"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) WebReconX/1.0.0'
        }

    def fetch_robots_txt(self) -> Dict[str, Any]:
        """Passive fetch and basic parse of robots.txt."""
        url = f"{self.root_url}/robots.txt"
        logger.info(f"Checking for robots.txt at {url}")
        
        result = {
            "exists": False,
            "url": url,
            "status_code": 0,
            "disallowed_paths": [],
            "sitemaps": [],
            "raw": ""
        }

        try:
            res = requests.get(url, headers=self.headers, timeout=self.timeout)
            result["status_code"] = res.status_code
            if res.status_code == 200:
                result["exists"] = True
                result["raw"] = res.text
                
                # Basic parsing
                for line in res.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ':' in line:
                        key, val = line.split(':', 1)
                        key = key.strip().lower()
                        val = val.strip()
                        if key == 'disallow':
                            result["disallowed_paths"].append(val)
                        elif key == 'sitemap':
                            result["sitemaps"].append(val)
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch robots.txt: {e}")

        return result

    def fetch_sitemap_xml(self) -> Dict[str, Any]:
        """Passive fetch and parse of sitemap.xml."""
        url = f"{self.root_url}/sitemap.xml"
        logger.info(f"Checking for sitemap.xml at {url}")
        
        result = {
            "exists": False,
            "url": url,
            "status_code": 0,
            "urls": [],
            "raw": ""
        }

        try:
            res = requests.get(url, headers=self.headers, timeout=self.timeout)
            result["status_code"] = res.status_code
            if res.status_code == 200:
                result["exists"] = True
                result["raw"] = res.text[:2000]  # Store first 2000 chars of raw content
                
                # Parse XML to find <loc> tags
                try:
                    root = ET.fromstring(res.content)
                    # Handle namespacing if present
                    namespaces = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                    # Find loc nodes
                    locs = root.findall('.//ns:loc', namespaces)
                    if not locs:
                        # Fallback search without namespace
                        locs = root.findall('.//loc')
                    
                    for loc in locs:
                        if loc.text:
                            result["urls"].append(loc.text.strip())
                except ET.ParseError:
                    # Not valid XML, search with simple regex
                    import re
                    matches = re.findall(r'<loc>(.*?)</loc>', res.text, re.IGNORECASE)
                    result["urls"] = [m.strip() for m in matches]
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch sitemap.xml: {e}")

        return result

    def gather_recon_summary(self, crawled_pages: Dict[str, Dict]) -> Dict[str, Any]:
        """Aggregates crawler data and endpoints into a recon summary."""
        total_size = sum(page.get("response_size", 0) for page in crawled_pages.values())
        status_counts = {}
        for page in crawled_pages.values():
            status = page.get("status_code", 0)
            status_counts[status] = status_counts.get(status, 0) + 1

        robots = self.fetch_robots_txt()
        sitemap = self.fetch_sitemap_xml()

        return {
            "total_pages_scanned": len(crawled_pages),
            "total_response_size_bytes": total_size,
            "status_codes_distribution": status_counts,
            "robots_txt": robots,
            "sitemap_xml": sitemap
        }
