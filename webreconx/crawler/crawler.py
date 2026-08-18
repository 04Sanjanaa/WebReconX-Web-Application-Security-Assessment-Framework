import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Tuple, Optional
from webreconx.core.validator import TargetValidator

logger = logging.getLogger("webreconx.crawler")

class WebCrawler:
    def __init__(self, base_url: str, validator: TargetValidator, max_depth: int = 2, max_pages: int = 50, timeout: float = 5.0):
        self.base_url = validator.normalize_url(base_url)
        self.validator = validator
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited_urls: Set[str] = set()
        # Queue storing tuples of (url, current_depth)
        self.queue: List[Tuple[str, int]] = [(self.base_url, 0)]
        self.pages_data: Dict[str, Dict] = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) WebReconX/1.0.0'
        }

    def extract_title(self, soup: BeautifulSoup) -> str:
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        return ""

    def extract_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        links = []
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            
            # Resolve relative URLs
            full_url = urljoin(current_url, href)
            try:
                normalized = self.validator.normalize_url(full_url)
                links.append(normalized)
            except ValueError:
                # Ignore malformed URLs
                continue
        return links

    def crawl_page(self, url: str, depth: int) -> Optional[Dict]:
        """Fetches a page, handles redirects manually to validate scope, and returns page data."""
        self.visited_urls.add(url)
        logger.info(f"Crawling URL: {url} at depth {depth}")

        current_url = url
        redirects_followed = []
        response = None
        max_redirect_limit = 5

        # Manual redirect loop to enforce scope validation
        for _ in range(max_redirect_limit):
            try:
                res = requests.get(
                    current_url, 
                    headers=self.headers, 
                    timeout=self.timeout, 
                    allow_redirects=False
                )
            except requests.RequestException as e:
                logger.error(f"Error requesting {current_url}: {e}")
                return None

            # Handle redirection status codes
            if res.status_code in (301, 302, 303, 307, 308):
                loc = res.headers.get("Location")
                if not loc:
                    response = res
                    break
                
                next_url = urljoin(current_url, loc)
                try:
                    next_url_norm = self.validator.normalize_url(next_url)
                except ValueError:
                    logger.warning(f"Redirect destination is malformed: {next_url}")
                    return None

                # Scope restriction check for redirects
                if not self.validator.is_in_scope(next_url_norm, self.base_url):
                    logger.warning(f"Redirect blocked: Destination {next_url_norm} is out of scope!")
                    # Store redirect information but do not visit
                    redirects_followed.append(next_url_norm)
                    response = res
                    break

                redirects_followed.append(next_url_norm)
                current_url = next_url_norm
            else:
                response = res
                break

        if not response:
            return None

        # Build response details
        page_info = {
            "url": url,
            "final_url": current_url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_type": response.headers.get("Content-Type", ""),
            "response_size": len(response.content),
            "redirects": redirects_followed,
            "title": "",
            "links": [],
            "body": ""
        }

        # Parse HTML if applicable
        if "text/html" in page_info["content_type"]:
            try:
                # Use response.text and fallback to encoding
                response.encoding = response.apparent_encoding or "utf-8"
                soup = BeautifulSoup(response.text, 'html.parser')
                page_info["title"] = self.extract_title(soup)
                page_info["links"] = self.extract_links(soup, current_url)
                page_info["body"] = response.text
            except Exception as e:
                logger.error(f"HTML parsing error on {current_url}: {e}")

        return page_info

    def start(self) -> Dict[str, Dict]:
        """Orchestrates the crawling process based on configured limits."""
        pages_scanned_count = 0
        
        while self.queue and pages_scanned_count < self.max_pages:
            url, depth = self.queue.pop(0)

            # Skip if already visited under standard loop check
            # (Note: we add it to visited_urls upon crawling, so this handles duplicates)
            if url in self.pages_data:
                continue

            page_info = self.crawl_page(url, depth)
            if not page_info:
                continue

            self.pages_data[url] = page_info
            pages_scanned_count += 1

            # Queue child links if depth allows
            if depth < self.max_depth:
                for link in page_info["links"]:
                    if link not in self.visited_urls and link not in [q[0] for q in self.queue]:
                        # Confirm the link is in scope
                        if self.validator.is_in_scope(link, self.base_url):
                            self.queue.append((link, depth + 1))
                            
        return self.pages_data
