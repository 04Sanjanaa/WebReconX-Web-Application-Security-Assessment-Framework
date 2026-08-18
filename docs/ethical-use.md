# Ethical Hacking & Safety Guidelines

WebReconX is built exclusively for educational purposes, security audits, and authorized assessment portfolios. Scanning systems without explicit, written digital authorization is illegal and unethical.

## Legal Compliance

When using WebReconX, you must comply with all local, national, and international cybersecurity laws, including:
- **Computer Fraud and Abuse Act (CFAA)** (United States)
- **Computer Misuse Act 1990** (United Kingdom)
- **General Data Protection Regulation (GDPR)** (European Union, particularly concerning data interception)

## Safeguards Built into WebReconX

To prevent accidental scanning and protect unauthorized endpoints, the framework implements several strict technical controls:

### 1. Loopback Restriction for Lab Mode
The `--mode lab` command is strictly restricted to loopback interfaces (`127.0.0.1`, `localhost`, `::1`). Attempts to run lab-mode checks (which test for sensitive files like `.env` and `.git/config`) against public domains will trigger an exception and immediately exit before any request is dispatched.

### 2. Same-Domain Scope Restriction
The crawler is restricted to the netloc of the target URL. Any parsed links pointing to subdomains or external domains are automatically categorized as out-of-scope and discarded.

### 3. Redirect Validation
When following redirects, the crawler halts automatic redirects, resolves the redirected path, and checks it against the scope validator *before* sending the request. This prevents the scanner from being redirected out of scope (e.g., if a login form redirects to an external OAuth provider).

### 4. Non-Destructive Scanning
WebReconX does not implement active exploitation methods such as SQL injection payloads, remote command execution commands, brute-forcing accounts, or script injections. All operations are restricted to passive HTTP response headers, metadata checks, and presence audits.
