import argparse
import sys
import os
import json
import logging
from webreconx.core.engine import ScanEngine
from webreconx.reporting.reporter import ScanReporter
from webreconx.core.finding import Finding
from webreconx.testlab.app import run_lab

# Setup standard logging configuration
logging.basicConfig(
    filename='webreconx.log',
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

logger = logging.getLogger("webreconx.cli")

VERSION = "1.0.0"

def safe_print(text: str, fallback: str):
    try:
        print(text)
    except UnicodeEncodeError:
        print(fallback)

def print_banner(mode: str = ""):
    banner = f"""
╔══════════════════════════════════════════════╗
║                  WebReconX                   ║
║  Web Application Security Assessment Tool    ║
║               Version: {VERSION}                 ║
╚══════════════════════════════════════════════╝"""
    fallback = f"""
+----------------------------------------------+
|                  WebReconX                   |
|  Web Application Security Assessment Tool    |
|               Version: {VERSION}                 |
+----------------------------------------------+"""
    safe_print(banner, fallback)
    if mode.upper() == "LAB":
        print("  *** AUTHORIZED LOCAL LAB TESTING MODE ACTIVE ***  ")
        print("----------------------------------------------------")

def handle_scan(args):
    print_banner(args.mode)
    
    # Check if target resolves to localhost in lab mode, engine does this too but we handle CLI validation early
    if args.mode == "lab":
        # Check if URL looks like local
        from urllib.parse import urlparse
        hostname = urlparse(args.url).hostname or args.url
        if hostname.lower() not in ("localhost", "127.0.0.1", "::1") and not hostname.endswith(".local"):
            # Try to resolve to make sure it's localhost
            import socket
            try:
                ip = socket.gethostbyname(hostname)
                if not ip.startswith("127.") and ip != "::1":
                    print(f"[!] Error: Lab mode is restricted to localhost/loopback targets.")
                    print(f"    Target '{args.url}' resolved to '{ip}', which is not a local address.")
                    sys.exit(1)
            except Exception:
                print(f"[!] Error: Lab mode is restricted to localhost targets. Could not resolve '{hostname}'.")
                sys.exit(1)

    # Opt-in check for sensitive paths on public targets
    if args.authorized_sensitive_checks and args.mode != "lab":
        print("[WARNING] You have enabled authorized sensitive checks (--authorized-sensitive-checks) on a non-lab target.")
        print("[WARNING] Make sure you have explicit authorization to request potentially sensitive paths like /.env and /.git/config.")
        confirm = input("Confirm you have explicit authorization to perform these checks (y/N): ")
        if confirm.lower() != 'y':
            print("Aborting sensitive path checks.")
            sys.exit(1)

    print(f"Target   : {args.url}")
    print(f"Mode     : {args.mode.upper()}")
    print("Initializing scan, please wait...")

    try:
        engine = ScanEngine(
            mode=args.mode,
            max_depth=args.depth,
            max_pages=args.max_pages,
            timeout=args.timeout,
            authorized_sensitive_checks=args.authorized_sensitive_checks
        )
        report_data = engine.run_scan(args.url)
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        logger.exception("Scan failed due to exception:")
        sys.exit(1)

    # Output scan summary
    print(f"Pages    : {report_data['pages_scanned']}")
    print(f"Duration : {report_data['duration_seconds']}s")
    print(f"Risk Score: {report_data['risk_score']} / 10")
    print(f"Risk Level: {report_data['risk_level']}")

    print("\nFindings")
    safe_print("──────────────────────────────────────────────", "----------------------------------------------")
    findings = report_data["findings"]
    if not findings:
        print("[INFO] No vulnerabilities detected.")
    else:
        # Sort findings by severity weight
        from webreconx.scoring.scorer import SEVERITY_WEIGHTS
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_WEIGHTS.get(f.severity.upper(), 0.0), reverse=True)
        for f in sorted_findings:
            print(f"[{f.severity.upper()}] {f.title}")

    # Report writing
    os.makedirs("reports", exist_ok=True)
    json_path = "reports/scan.json"
    html_path = "reports/scan.html"
    csv_path = "reports/scan.csv"

    reporter = ScanReporter(report_data)
    reporter.to_json(json_path)
    reporter.to_html(html_path)
    reporter.to_csv(csv_path)

    print("\nReports")
    safe_print("──────────────────────────────────────────────", "----------------------------------------------")
    safe_print(f"✓ JSON → {json_path}", f"  [+] JSON -> {json_path}")
    safe_print(f"✓ HTML → {html_path}", f"  [+] HTML -> {html_path}")
    safe_print(f"✓ CSV  → {csv_path}", f"  [+] CSV  -> {csv_path}")
    print()

def handle_report(args):
    print_banner()
    print(f"Converting report from: {args.input}")
    
    if not os.path.exists(args.input):
        print(f"[!] Error: Input file '{args.input}' not found.")
        sys.exit(1)

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
            
        # Rehydrate findings list
        findings_raw = raw_data.get("findings", [])
        findings_list = []
        for f in findings_raw:
            findings_list.append(Finding(
                id=f["id"],
                title=f["title"],
                severity=f["severity"],
                confidence=f["confidence"],
                category=f["category"],
                owasp_mapping=f["owasp_mapping"],
                url=f["url"],
                evidence=f["evidence"],
                description=f["description"],
                impact=f["impact"],
                remediation=f["remediation"],
                references=f.get("references", [])
            ))
        raw_data["findings"] = findings_list
        
        reporter = ScanReporter(raw_data)
        
        fmt = args.format.lower()
        if args.output:
            out_path = args.output
        else:
            out_path = f"reports/scan_converted.{fmt}"

        if fmt == "html":
            reporter.to_html(out_path)
        elif fmt == "csv":
            reporter.to_csv(out_path)
        elif fmt == "json":
            reporter.to_json(out_path)
        else:
            print(f"[!] Unsupported format: {fmt}")
            sys.exit(1)

        print(f"✓ Successfully generated {fmt.upper()} report at: {out_path}")
    except Exception as e:
        print(f"[!] Error converting report: {e}")
        sys.exit(1)

def handle_lab(args):
    run_lab(args.port)

def main():
    parser = argparse.ArgumentParser(
        description="WebReconX — Modular Web Application Security Reconnaissance & Assessment Framework"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # SCAN subcommand
    scan_parser = subparsers.add_parser("scan", help="Run a security scan against a web application target")
    scan_parser.add_argument("--url", required=True, help="Base URL of the target to scan")
    scan_parser.add_argument("--mode", choices=["passive", "lab"], default="passive", 
                             help="Scanning mode: passive (safe recon) or lab (localhost only)")
    scan_parser.add_argument("--depth", type=int, default=2, help="Max link crawling depth (default: 2)")
    scan_parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    scan_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP request timeout in seconds (default: 5.0)")
    scan_parser.add_argument("--authorized-sensitive-checks", action="store_true", 
                             help="Explicit opt-in to scan sensitive file paths on authorized public targets")

    # REPORT subcommand
    report_parser = subparsers.add_parser("report", help="Generate or convert report files from existing JSON output")
    report_parser.add_argument("--input", required=True, help="Path to input scan.json report")
    report_parser.add_argument("--format", choices=["html", "csv", "json"], default="html", 
                               help="Format to output (default: html)")
    report_parser.add_argument("--output", help="Optional output path (defaults to reports/scan_converted.<format>)")

    # LAB subcommand
    lab_parser = subparsers.add_parser("lab", help="Run the local vulnerable test laboratory")
    lab_parser.add_argument("--port", type=int, default=5000, help="Port to run Flask test lab (default: 5000)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        handle_scan(args)
    elif args.command == "report":
        handle_report(args)
    elif args.command == "lab":
        handle_lab(args)

if __name__ == "__main__":
    main()
