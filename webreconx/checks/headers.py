from typing import List, Dict
from webreconx.checks.base import BaseCheck
from webreconx.core.finding import Finding

class HeaderSecurityCheck(BaseCheck):
    def run(self, url: str, headers: Dict[str, str], body: str, mode: str = "passive") -> List[Finding]:
        findings: List[Finding] = []
        
        # Normalize header keys for case insensitivity
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # 1. Content-Security-Policy
        if "content-security-policy" not in headers_lower:
            findings.append(Finding(
                id="SEC-HDR-CSP",
                title="Missing Content-Security-Policy (CSP) Header",
                severity="HIGH",
                confidence="HIGH",
                category="Security Headers",
                owasp_mapping="A05:2021-Security Misconfiguration",
                url=url,
                evidence="No Content-Security-Policy header detected in response headers.",
                description="The Content-Security-Policy (CSP) header is missing. CSP is a powerful security header that prevents Cross-Site Scripting (XSS), clickjacking, and other data injection attacks by restricting the origins from which scripts, styles, and other resources can be loaded.",
                impact="Attackers could exploit vulnerabilities like Cross-Site Scripting (XSS) to execute arbitrary scripts in the context of the user's browser, leading to session hijacking, defacement, or data theft.",
                remediation="Implement a Content-Security-Policy header. Start with a safe default policy: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';",
                references=["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"]
            ))

        # 2. Strict-Transport-Security (HSTS)
        # HSTS is only valid for HTTPS responses, check if HTTPS or if we can evaluate it
        is_https = url.lower().startswith("https://")
        if is_https and "strict-transport-security" not in headers_lower:
            findings.append(Finding(
                id="SEC-HDR-HSTS",
                title="Missing Strict-Transport-Security (HSTS) Header",
                severity="MEDIUM",
                confidence="HIGH",
                category="Security Headers",
                owasp_mapping="A05:2021-Security Misconfiguration",
                url=url,
                evidence="No Strict-Transport-Security header detected in response headers.",
                description="The Strict-Transport-Security (HSTS) header is missing. HSTS informs browser clients that they should only interact with the server using secure HTTPS connections, preventing protocol downgrade attacks.",
                impact="Attackers on the same network could perform Man-in-the-Middle (MITM) attacks and intercept sensitive communication via SSL stripping / protocol downgrade.",
                remediation="Add the Strict-Transport-Security header to all HTTPS responses. Example: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                references=["https://owasp.org/www-project-secure-headers/", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
            ))

        # 3. X-Frame-Options (XFO)
        # Note: If CSP has frame-ancestors, that's also valid, but XFO is checked for compatibility
        if "x-frame-options" not in headers_lower:
            # Check if CSP has frame-ancestors to avoid duplicate high-severity findings
            csp_val = headers_lower.get("content-security-policy", "")
            has_frame_ancestors = "frame-ancestors" in csp_val
            
            if not has_frame_ancestors:
                findings.append(Finding(
                    id="SEC-HDR-XFO",
                    title="Missing X-Frame-Options (Clickjacking Exposure)",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="Security Headers",
                    owasp_mapping="A05:2021-Security Misconfiguration",
                    url=url,
                    evidence="No X-Frame-Options header (or frame-ancestors CSP directive) detected in response headers.",
                    description="The X-Frame-Options header is missing. It controls whether the site can be embedded in an iframe on third-party sites.",
                    impact="Without this protection, attackers can craft clickjacking pages, embedding this target website in an invisible iframe and tricking users into executing unintended actions.",
                    remediation="Configure the server to return the X-Frame-Options header. Recommended settings: X-Frame-Options: SAMEORIGIN or X-Frame-Options: DENY. Alternatively, specify frame-ancestors 'self' in CSP.",
                    references=["https://owasp.org/www-community/attacks/Clickjacking", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"]
                ))

        # 4. X-Content-Type-Options (XCTO)
        if "x-content-type-options" not in headers_lower or headers_lower["x-content-type-options"].strip().lower() != "nosniff":
            findings.append(Finding(
                id="SEC-HDR-XCTO",
                title="Missing or Insecure X-Content-Type-Options (MIME Sniffing Exposure)",
                severity="LOW",
                confidence="HIGH",
                category="Security Headers",
                owasp_mapping="A05:2021-Security Misconfiguration",
                url=url,
                evidence=f"X-Content-Type-Options is {headers_lower.get('x-content-type-options', 'missing')}.",
                description="The X-Content-Type-Options header is missing or not set to 'nosniff'. This header prevents browsers from sniffing files as another MIME type than what is defined in the Content-Type header.",
                impact="Allows attackers to perform cross-site scripting (XSS) via MIME-sniffing, for example by uploading a malicious image containing script markup that the browser executes as HTML.",
                remediation="Ensure the server serves the header: X-Content-Type-Options: nosniff",
                references=["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
            ))

        # 5. Referrer-Policy
        if "referrer-policy" not in headers_lower:
            findings.append(Finding(
                id="SEC-HDR-REF",
                title="Missing Referrer-Policy Header",
                severity="LOW",
                confidence="HIGH",
                category="Security Headers",
                owasp_mapping="A05:2021-Security Misconfiguration",
                url=url,
                evidence="No Referrer-Policy header detected in response headers.",
                description="The Referrer-Policy header is missing. This header controls how much referrer information is sent along with HTTP requests.",
                impact="Sensitive URLs containing tokens, session IDs, or private data could leak to external analytics/third-party domains in the Referer header.",
                remediation="Add the Referrer-Policy header. E.g., Referrer-Policy: strict-origin-when-cross-origin",
                references=["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"]
            ))

        # 6. Permissions-Policy
        if "permissions-policy" not in headers_lower:
            findings.append(Finding(
                id="SEC-HDR-PERM",
                title="Missing Permissions-Policy Header",
                severity="LOW",
                confidence="HIGH",
                category="Security Headers",
                owasp_mapping="A05:2021-Security Misconfiguration",
                url=url,
                evidence="No Permissions-Policy header detected in response headers.",
                description="The Permissions-Policy header is missing. It allows developers to restrict which browser APIs and hardware resources (e.g. camera, microphone, geolocation) can be accessed by the page.",
                impact="If the site has an XSS vulnerability, the lack of restriction increases the attack surface, potentially allowing attackers to exploit browser APIs.",
                remediation="Add the Permissions-Policy header. Example: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                references=["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permission-Policy"]
            ))

        return findings
