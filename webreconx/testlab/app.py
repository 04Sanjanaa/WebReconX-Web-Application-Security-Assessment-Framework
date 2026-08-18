from flask import Flask, make_response, request, jsonify
import sys

app = Flask(__name__)

# Branding header to return on all lab pages
LAB_BRANDING = """
<div style="background-color: #7f1d1d; color: white; padding: 1rem; text-align: center; font-family: sans-serif; font-weight: bold; border-bottom: 4px solid #ef4444;">
    WebReconX Deliberately Vulnerable Lab &mdash; Authorized Local Testing Only
</div>
"""

HTML_LAYOUT = """
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; margin: 0; padding: 0; background: #f8fafc; color: #1e293b; }}
        .content {{ padding: 2rem; max-width: 800px; margin: 0 auto; }}
        a {{ color: #2563eb; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        ul {{ line-height: 1.8; }}
        .card {{ background: white; border: 1px solid #e2e8f0; padding: 1.5rem; border-radius: 8px; margin-top: 1rem; }}
    </style>
</head>
<body>
    {branding}
    <div class="content">
        <h1>{title}</h1>
        {body}
    </div>
</body>
</html>
"""

# Home Page - Missing all security headers
@app.route('/')
@app.route('/vulnerable')
def index():
    body_content = """
    <p>Welcome to the WebReconX Test Lab. This application contains intentional security misconfigurations and insecure designs for validation testing.</p>
    <div class="card">
        <h3>Available Endpoints</h3>
        <ul>
            <li><a href="/secure">/secure</a> &mdash; Fully secure endpoint with headers and HSTS simulated.</li>
            <li><a href="/safe-endpoint">/safe-endpoint</a> &mdash; Synonym for secure endpoint.</li>
            <li><a href="/insecure-cookies">/insecure-cookies</a> &mdash; Sets cookies missing HttpOnly, Secure, and SameSite.</li>
            <li><a href="/secure-cookies">/secure-cookies</a> &mdash; Sets cookies with HttpOnly, Secure, and SameSite=Lax.</li>
            <li><a href="/info-disclosure">/info-disclosure</a> &mdash; Leaks system version details in body and headers.</li>
            <li><a href="/directory-listing">/directory-listing</a> &mdash; Simulates an exposed directory index.</li>
        </ul>
    </div>
    """
    html = HTML_LAYOUT.format(title="Vulnerable Test Lab Home", branding=LAB_BRANDING, body=body_content)
    resp = make_response(html)
    # Ensure no security headers are present
    return resp

# Secure endpoint
@app.route('/secure')
@app.route('/safe-endpoint')
def secure():
    body_content = """
    <p>This endpoint is configured with a robust set of security headers and secure cookie configurations.</p>
    <p><a href="/">Back to Home</a></p>
    """
    html = HTML_LAYOUT.format(title="Secure Lab Page", branding=LAB_BRANDING, body=body_content)
    resp = make_response(html)
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; frame-ancestors 'self';"
    resp.headers['X-Frame-Options'] = "SAMEORIGIN"
    resp.headers['X-Content-Type-Options'] = "nosniff"
    resp.headers['Referrer-Policy'] = "strict-origin-when-cross-origin"
    resp.headers['Permissions-Policy'] = "camera=(), microphone=(), geolocation=()"
    resp.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains"
    return resp

# Insecure Cookies
@app.route('/insecure-cookies')
def insecure_cookies():
    body_content = """
    <p>This page has set an insecure cookie <code>session_id</code>. Check your developer console or scanner findings.</p>
    <p><a href="/">Back to Home</a></p>
    """
    html = HTML_LAYOUT.format(title="Insecure Cookies Test", branding=LAB_BRANDING, body=body_content)
    resp = make_response(html)
    # Set cookies with no flags
    resp.set_cookie('session_id', 'vulnerable123')
    resp.set_cookie('tracking_pref', 'light')
    return resp

# Secure Cookies
@app.route('/secure-cookies')
def secure_cookies():
    body_content = """
    <p>This page has set a secure cookie <code>secure_session</code> with HttpOnly, Secure, and SameSite=Lax flags.</p>
    <p><a href="/">Back to Home</a></p>
    """
    html = HTML_LAYOUT.format(title="Secure Cookies Test", branding=LAB_BRANDING, body=body_content)
    resp = make_response(html)
    # Set cookies with proper flags (Secure=True will be parsed by scanner even on HTTP localhost)
    resp.set_cookie('secure_session', 'supersecure456', httponly=True, secure=True, samesite='Lax')
    return resp

# Info Disclosure
@app.route('/info-disclosure')
def info_disclosure():
    body_content = """
    <p>This page discloses server metadata inside headers and response body.</p>
    <div class="card">
        <p>Internal Details: Python v3.10.12, running on Flask v2.2.3</p>
    </div>
    <p><a href="/">Back to Home</a></p>
    """
    html = HTML_LAYOUT.format(title="Information Disclosure Test", branding=LAB_BRANDING, body=body_content)
    resp = make_response(html)
    resp.headers['Server'] = "Werkzeug/2.2.3 Python/3.10.12"
    resp.headers['X-Powered-By'] = "Flask/2.2.3"
    return resp

# Directory Listing
@app.route('/directory-listing')
def directory_listing():
    body_content = """
    <p>Below is a directory layout exposing local files:</p>
    <div class="card">
        <h3>Index of /files</h3>
        <ul>
            <li><a href="/">Parent Directory</a></li>
            <li><a href="/secrets.txt">secrets.txt</a></li>
            <li><a href="/backup.zip">backup.zip</a></li>
        </ul>
    </div>
    <p><a href="/">Back to Home</a></p>
    """
    html = HTML_LAYOUT.format(title="Directory Listing Test", branding=LAB_BRANDING, body=body_content)
    return make_response(html)

# Simulating sensitive files for Lab Mode checks
@app.route('/.env')
def env_expose():
    # Simulated environment file
    return "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=supersecurepassword123\nSECRET_KEY=webreconx_secret_token", 200, {'Content-Type': 'text/plain'}

@app.route('/.git/config')
def git_expose():
    # Simulated git config
    git_config = """[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
\tlogallrefupdates = true
\tsymlinks = false
\tignorecase = true
[remote "origin"]
\turl = https://github.com/rohitajariwal/web-app-security-scanner.git
"""
    return git_config, 200, {'Content-Type': 'text/plain'}

@app.route('/backup.zip')
def backup_expose():
    # Simulated zip file
    dummy_zip_content = b"PK\x03\x04\n\x00\x00\x00\x00\x00Dummy zip file content"
    return dummy_zip_content, 200, {'Content-Type': 'application/zip'}

@app.route('/config.php.bak')
def config_bak_expose():
    # Simulated config backup file
    php_bak = """<?php
$db_host = "localhost";
$db_user = "db_admin";
$db_pass = "adminPassword123!";
$db_name = "production_db";
?>"""
    return php_bak, 200, {'Content-Type': 'text/plain'}

def run_lab(port=5000):
    print("----------------------------------------------------------------")
    print(" WebReconX Deliberately Vulnerable Lab Environment")
    print(" AUTHORIZED LOCAL TESTING ONLY")
    print(f" Starting lab server on http://127.0.0.1:{port}")
    print(" Press Ctrl+C to terminate.")
    print("----------------------------------------------------------------")
    app.run(host='127.0.0.1', port=port, debug=False)

if __name__ == '__main__':
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_lab(port)
