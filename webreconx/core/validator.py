import socket
import re
from urllib.parse import urlparse, urlunparse

class TargetValidator:
    def __init__(self, mode: str = "passive"):
        self.mode = mode.lower()

    def normalize_url(self, url: str) -> str:
        """Normalizes a URL to a standard format."""
        if not url:
            raise ValueError("URL cannot be empty")
        
        # Ensure scheme is present, default to http if missing
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9.+\-]*://', url):
            url = "http://" + url
            
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Malformed URL: {e}")

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme '{scheme}'. Only http and https are allowed.")

        netloc = parsed.netloc.lower()
        if not netloc:
            raise ValueError("URL is missing a valid hostname")

        # Remove standard ports to normalize
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        path = parsed.path
        if not path:
            path = "/"
        elif len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")

        # Return reconstructed URL without fragment
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))

    def is_localhost(self, url: str) -> bool:
        """Checks if a URL resolves to localhost/loopback."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False
            
            if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
                return True

            # Perform DNS resolution to check if it resolves to loopback IP
            ip = socket.gethostbyname(hostname)
            return ip.startswith("127.") or ip == "::1"
        except Exception:
            return False

    def validate_target(self, url: str) -> str:
        """
        Validates the target URL.
        Normalizes, checks scheme, and enforces mode/localhost rules.
        """
        normalized = self.normalize_url(url)
        
        # If lab mode, target MUST be localhost
        if self.mode == "lab":
            if not self.is_localhost(normalized):
                raise ValueError(
                    "LAB mode is restricted to localhost targets (127.0.0.1, localhost, ::1) only."
                )
        return normalized

    def is_in_scope(self, url: str, base_url: str) -> bool:
        """
        Determines if a URL is in scope (shares the same scheme, domain and port).
        """
        try:
            parsed_url = urlparse(self.normalize_url(url))
            parsed_base = urlparse(self.normalize_url(base_url))
            
            # Match scheme and netloc (netloc includes domain and port)
            return (parsed_url.scheme == parsed_base.scheme and 
                    parsed_url.netloc == parsed_base.netloc)
        except Exception:
            return False
