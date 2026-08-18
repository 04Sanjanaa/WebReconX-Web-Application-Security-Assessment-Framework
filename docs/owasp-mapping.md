# OWASP Top 10 Mapping Logic & Justifications

WebReconX maps every identified security finding to an category from the **OWASP Top 10 (2021)**. In security assessments, accurate categorization is crucial for compliance, threat modeling, and explaining findings to stakeholders.

## Vulnerability to OWASP Mapping Table

| Finding ID | Finding Title | Severity | OWASP Mapping | Justification |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-HDR-CSP** | Missing Content-Security-Policy (CSP) | HIGH | **A05:2021-Security Misconfiguration** | Failure to configure a policy to restrict resource loading, increasing vulnerability to XSS and injection attacks. |
| **SEC-HDR-HSTS** | Missing Strict-Transport-Security (HSTS) | MEDIUM | **A05:2021-Security Misconfiguration** | Missing HTTP header configuration to force TLS connection, facilitating network eavesdropping and downgrade attacks. |
| **SEC-HDR-XFO** | Missing X-Frame-Options (XFO) | MEDIUM | **A05:2021-Security Misconfiguration** | Missing security header configuration allowing framing of the website, which enables clickjacking attacks. |
| **SEC-HDR-XCTO** | Missing X-Content-Type-Options (XCTO) | LOW | **A05:2021-Security Misconfiguration** | Failure to configure MIME sniffing protection, exposing users to cross-site scripting via file upload/parsing mismatches. |
| **SEC-HDR-REF** | Missing Referrer-Policy Header | LOW | **A05:2021-Security Misconfiguration** | Missing header allows leaking sensitive path tokens in HTTP referrers. |
| **SEC-HDR-PERM** | Missing Permissions-Policy Header | LOW | **A05:2021-Security Misconfiguration** | Failure to restrict browser features and hardware APIs (e.g. camera, microphone), expanding the client-side attack surface. |
| **COOKIE-NO-HTTPONLY** | Cookie Missing 'HttpOnly' Attribute | MEDIUM | **A05:2021-Security Misconfiguration** | Missing server configuration flags on session or tracking cookies, allowing access via client-side scripting. |
| **COOKIE-NO-SECURE** | Cookie Missing 'Secure' Attribute | MEDIUM | **A05:2021-Security Misconfiguration** | Cookie configuration error allowing transmission over plaintext HTTP. |
| **COOKIE-NO-SAMESITE**| Cookie Insecure 'SameSite' Configuration | LOW | **A01:2021-Broken Access Control** | Failure to enforce cross-origin request boundaries on session state, making requests vulnerable to CSRF. |
| **INSECURE-HTTP** | Insecure HTTP Protocol Usage | MEDIUM | **A02:2021-Cryptographic Failures** | Use of unencrypted transport (HTTP) for transmission of potentially sensitive application data. |
| **INFO-DISC-SERVER**| Detailed Server Version Disclosure | LOW | **A05:2021-Security Misconfiguration** | Exposing detailed software version stamps which assists attackers in version-specific exploit planning. |
| **INFO-DISC-SERVER-GEN**| Server Header Disclosed | INFO | **Informational / No direct OWASP Top 10 mapping** | Exposing standard server signatures (e.g. nginx, Apache) is standard behavior and not directly a misconfiguration. |
| **INFO-DISC-POWERED**| X-Powered-By Header Information Disclosure | LOW | **A05:2021-Security Misconfiguration** | Exposing engine versions/technologies. |
| **DIR-LIST-EXPOSED**| Exposed Directory Listing Layout | MEDIUM | **A01:2021-Broken Access Control** | Web server configured to display files inside a directory to unauthenticated web browsers. |
| **SENSITIVE-ENV** | Exposed Environment Configuration File (.env) | CRITICAL | **A05:2021-Security Misconfiguration** | Storing database passwords, private keys, and application secrets in accessible config paths in production. |
| **SENSITIVE-GIT** | Exposed Git Repository Configuration | HIGH | **A05:2021-Security Misconfiguration** | Exposing version control structure and history. |
| **SENSITIVE-BACKUP-ZIP** | Exposed Backup Archive File (backup.zip) | MEDIUM | **A05:2021-Security Misconfiguration** | Leaving code, data, or config backups in the public web root. |
| **SENSITIVE-CONFIG-BAK** | Exposed Backup Configuration File (config.php.bak) | HIGH | **A05:2021-Security Misconfiguration** | Storing config backups in a format that bypasses compilation and is served as plaintext. |

---

## Detailed Justification Principles

### A05:2021-Security Misconfiguration
This category represents the largest share of our findings. The OWASP definition states:
> "Security misconfiguration can happen when the application is configured with default accounts, debugging enabled, or when security headers are not set or set to insecure values."
Since WebReconX acts as a passive configuration auditor, missing headers (CSP, HSTS, XFO) and missing cookie attributes are classified here. They are configurations under the direct control of the administrator that can be toggled to harden the environment.

### A01:2021-Broken Access Control
This category applies to authorization and access enforcement errors:
- **SameSite Cookie Attribute**: Direct control over cross-origin state transmission. A missing SameSite attribute allows third-party contexts to issue requests utilizing the user's active session, which is a failure of access control.
- **Directory Listing**: Allowing users to read directory tables and download non-linked raw resource assets is an access restriction bypass.

### A02:2021-Cryptographic Failures
- **Insecure HTTP Usage**: Transmitting data in cleartext is classified under cryptographic failures. The lack of transit encryption (TLS/HTTPS) fails to protect data integrity and confidentiality.

### Informational / No direct OWASP Top 10 mapping
- **Server Header Disclosed (Generic)**: Merely revealing that a web server uses a certain software family (like nginx or Apache) is not a vulnerability by itself, so it is marked as Informational. No direct OWASP Top 10 mapping is applied as it represents a default configuration rather than a security configuration vulnerability.
