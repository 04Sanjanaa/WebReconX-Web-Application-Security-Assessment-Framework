import re
from typing import List, Dict
from webreconx.checks.base import BaseCheck
from webreconx.core.finding import Finding

class CookieSecurityCheck(BaseCheck):
    def __init__(self):
        super().__init__()
        # Regex to split multiple Set-Cookie headers joined with commas (ignoring commas inside Expires=...)
        self.cookie_splitter = re.compile(r',\s*(?=[a-zA-Z0-9_\-]+[=])')

    def parse_cookie_directives(self, cookie_str: str) -> Dict[str, str]:
        """Parses cookie string directives into key-value pairs."""
        directives = {}
        parts = cookie_str.split(';')
        
        # First part is the cookie name=value
        if parts:
            name_val = parts[0].strip().split('=', 1)
            directives['name'] = name_val[0]
            directives['value'] = name_val[1] if len(name_val) > 1 else ""

        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue
            if '=' in part:
                k, v = part.split('=', 1)
                directives[k.strip().lower()] = v.strip().lower()
            else:
                directives[part.lower()] = "true"
                
        return directives

    def run(self, url: str, headers: Dict[str, str], body: str, mode: str = "passive") -> List[Finding]:
        findings: List[Finding] = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        set_cookie_val = headers_lower.get("set-cookie")
        
        if not set_cookie_val:
            return findings

        # Split multiple cookies
        cookie_strings = self.cookie_splitter.split(set_cookie_val)

        for cookie_str in cookie_strings:
            cookie_str = cookie_str.strip()
            if not cookie_str:
                continue

            directives = self.parse_cookie_directives(cookie_str)
            cookie_name = directives.get('name', 'Unknown')
            
            # Skip checking static tracking/layout cookies if desired, but check all for comprehensive audit
            # 1. HttpOnly Check
            if 'httponly' not in directives:
                findings.append(Finding(
                    id="COOKIE-NO-HTTPONLY",
                    title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Attribute",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="Cookie Security",
                    owasp_mapping="A05:2021-Security Misconfiguration",
                    url=url,
                    evidence=f"Set-Cookie: {cookie_str}",
                    description=f"The cookie '{cookie_name}' was set without the 'HttpOnly' attribute.",
                    impact="If the application is vulnerable to Cross-Site Scripting (XSS), an attacker can access this cookie via document.cookie. For session cookies, this leads to full session hijacking.",
                    remediation="Add the 'HttpOnly' flag when setting this cookie in the application backend or server configuration.",
                    references=["https://owasp.org/www-community/HttpOnly", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"]
                ))

            # 2. Secure Check
            # Only trigger if HSTS or page is HTTPS, or if it is a sensitive session-looking cookie
            # In general, not using Secure is always a finding unless testing on HTTP localhost, 
            # but even then, production deployment requires Secure.
            if 'secure' not in directives:
                findings.append(Finding(
                    id="COOKIE-NO-SECURE",
                    title=f"Cookie '{cookie_name}' Missing 'Secure' Attribute",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="Cookie Security",
                    owasp_mapping="A05:2021-Security Misconfiguration",
                    url=url,
                    evidence=f"Set-Cookie: {cookie_str}",
                    description=f"The cookie '{cookie_name}' was set without the 'Secure' attribute.",
                    impact="The cookie will be sent over unencrypted HTTP requests, leaving it vulnerable to interception by Man-in-the-Middle (MITM) attackers on the network path.",
                    remediation="Add the 'Secure' flag when setting the cookie, ensuring it is only transmitted over HTTPS connections.",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"]
                ))

            # 3. SameSite Check
            samesite_val = directives.get('samesite')
            if not samesite_val or samesite_val not in ('lax', 'strict'):
                findings.append(Finding(
                    id="COOKIE-NO-SAMESITE",
                    title=f"Cookie '{cookie_name}' Insecure 'SameSite' Configuration",
                    severity="LOW",
                    confidence="HIGH",
                    category="Cookie Security",
                    owasp_mapping="A01:2021-Broken Access Control",
                    url=url,
                    evidence=f"Set-Cookie: {cookie_str} (SameSite value: {samesite_val})",
                    description=f"The cookie '{cookie_name}' is missing a secure 'SameSite' attribute, or it is set to 'None'.",
                    impact="If SameSite is missing or set to 'None', the browser sends this cookie on cross-site requests. This exposes the user to Cross-Site Request Forgery (CSRF) attacks.",
                    remediation="Configure the 'SameSite' attribute to 'Lax' (recommended for general use) or 'Strict' (for highly sensitive actions).",
                    references=["https://owasp.org/www-community/SameSite", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"]
                ))

        return findings
