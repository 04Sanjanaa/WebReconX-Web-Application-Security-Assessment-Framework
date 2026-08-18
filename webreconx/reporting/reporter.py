import json
import csv
import os
import datetime
from typing import Dict, List, Any
from webreconx.core.finding import Finding

class ScanReporter:
    def __init__(self, scan_data: Dict[str, Any]):
        self.data = scan_data
        self.findings: List[Finding] = scan_data.get("findings", [])

    def to_json(self, filepath: str):
        """Generates a JSON report."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        
        # Serialize findings to dict
        report_dict = dict(self.data)
        report_dict["findings"] = [f.to_dict() for f in self.findings]
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=4)

    def to_csv(self, filepath: str):
        """Generates a CSV report."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        
        headers = [
            "id", "title", "severity", "confidence", "category", 
            "owasp_mapping", "url", "evidence", "description", 
            "impact", "remediation"
        ]
        
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for finding in self.findings:
                writer.writerow([
                    finding.id,
                    finding.title,
                    finding.severity,
                    finding.confidence,
                    finding.category,
                    finding.owasp_mapping,
                    finding.url,
                    finding.evidence,
                    finding.description.replace("\n", " "),
                    finding.impact.replace("\n", " "),
                    finding.remediation.replace("\n", " ")
                ])

    def to_html(self, filepath: str):
        """Generates a professional HTML report."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        
        # Build findings rows HTML
        findings_table_html = ""
        findings_details_html = ""
        
        # Color helper
        def get_color_class(sev: str) -> str:
            sev = sev.upper()
            if sev == "CRITICAL": return "severity-critical"
            if sev == "HIGH": return "severity-high"
            if sev == "MEDIUM": return "severity-medium"
            if sev == "LOW": return "severity-low"
            return "severity-info"

        if not self.findings:
            findings_table_html = "<tr><td colspan='5' style='text-align:center;'>No vulnerabilities identified.</td></tr>"
            findings_details_html = "<div class='no-findings'>No detailed findings to display.</div>"
        else:
            for idx, f in enumerate(self.findings, 1):
                color_class = get_color_class(f.severity)
                findings_table_html += f"""
                <tr>
                    <td><span class="badge {color_class}">{f.severity}</span></td>
                    <td><strong>{f.id}</strong></td>
                    <td><a href="#finding-{idx}">{f.title}</a></td>
                    <td>{f.owasp_mapping}</td>
                    <td class="text-muted" style="word-break: break-all;">{f.url}</td>
                </tr>
                """
                
                references_html = "".join([f"<li><a href='{ref}' target='_blank'>{ref}</a></li>" for ref in f.references])
                if not references_html:
                    references_html = "<li>No references provided.</li>"

                findings_details_html += f"""
                <div id="finding-{idx}" class="finding-card">
                    <div class="finding-card-header {color_class}-border">
                        <span class="badge {color_class}">{f.severity}</span>
                        <h3>{f.title}</h3>
                        <span class="finding-id">{f.id}</span>
                    </div>
                    <div class="finding-card-body">
                        <table class="table-compact">
                            <tr>
                                <th>Category</th>
                                <td>{f.category}</td>
                                <th>Confidence</th>
                                <td>{f.confidence}</td>
                            </tr>
                            <tr>
                                <th>OWASP Mapping</th>
                                <td>{f.owasp_mapping}</td>
                                <th>Affected URL</th>
                                <td style="word-break: break-all;"><a href="{f.url}" target="_blank">{f.url}</a></td>
                            </tr>
                        </table>
                        
                        <div class="section-sub">
                            <h4>Description</h4>
                            <p>{f.description}</p>
                        </div>
                        
                        <div class="section-sub">
                            <h4>Vulnerability Impact</h4>
                            <p>{f.impact}</p>
                        </div>
                        
                        <div class="section-sub">
                            <h4>Remediation Recommendations</h4>
                            <p>{f.remediation}</p>
                        </div>
                        
                        <div class="section-sub">
                            <h4>Evidence</h4>
                            <pre class="evidence-block"><code>{f.evidence}</code></pre>
                        </div>
                        
                        <div class="section-sub">
                            <h4>References</h4>
                            <ul>{references_html}</ul>
                        </div>
                    </div>
                </div>
                """

        # Tech stack format
        tech_list = self.data.get("recon_summary", {}).get("detected_technologies", [])
        tech_html = "".join([f"<span class='tech-pill'>{tech}</span>" for tech in tech_list])
        if not tech_html:
            tech_html = "<span class='text-muted'>No standard web technologies identified passively.</span>"

        # Robots.txt status
        robots_txt = self.data.get("recon_summary", {}).get("robots_txt", {})
        robots_status = f"Discovered ({len(robots_txt.get('disallowed_paths', []))} disallowed paths)" if robots_txt.get("exists") else "Not Found"
        
        # Sitemap status
        sitemap_xml = self.data.get("recon_summary", {}).get("sitemap_xml", {})
        sitemap_status = f"Discovered ({len(sitemap_xml.get('urls', []))} URLs)" if sitemap_xml.get("exists") else "Not Found"

        # Overall risk level coloring
        risk_level = self.data.get("risk_level", "INFO").upper()
        risk_color_class = get_color_class(risk_level)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebReconX Security Report - {self.data.get('target')}</title>
    <style>
        :root {{
            --primary: #1e293b;
            --background: #f8fafc;
            --surface: #ffffff;
            --text: #334155;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #10b981;
            --info: #3b82f6;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--background);
            color: var(--text);
            line-height: 1.5;
            margin: 0;
            padding: 0;
        }}

        header {{
            background-color: var(--primary);
            color: #ffffff;
            padding: 2rem;
            border-bottom: 4px solid var(--border);
        }}

        .container {{
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1.5rem;
        }}

        .grid-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }}

        .title-block h1 {{
            margin: 0;
            font-size: 2.25rem;
            font-weight: 700;
            letter-spacing: -0.05em;
        }}

        .title-block p {{
            margin: 0.25rem 0 0 0;
            color: #94a3b8;
            font-size: 1rem;
        }}

        .risk-badge-large {{
            padding: 1rem 2rem;
            border-radius: 8px;
            text-align: center;
            font-weight: 800;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        .risk-badge-large div {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.25rem;
        }}

        .risk-badge-large span {{
            font-size: 1.75rem;
        }}

        .grid-layout {{
            display: grid;
            grid-template-columns: 3fr 1fr;
            gap: 2rem;
            margin-top: 2rem;
        }}

        @media (max-width: 900px) {{
            .grid-layout {{
                grid-template-columns: 1fr;
            }}
        }}

        .card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }}

        .card h2 {{
            margin-top: 0;
            border-bottom: 2px solid var(--border);
            padding-bottom: 0.5rem;
            font-size: 1.25rem;
            color: var(--primary);
        }}

        table.table-report {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}

        table.table-report th, table.table-report td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}

        table.table-report th {{
            background-color: #f1f5f9;
            color: var(--primary);
            font-weight: 600;
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            color: #fff;
        }}

        .severity-critical {{ background-color: var(--critical); }}
        .severity-high {{ background-color: var(--high); }}
        .severity-medium {{ background-color: var(--medium); }}
        .severity-low {{ background-color: var(--low); }}
        .severity-info {{ background-color: var(--info); }}

        .severity-critical-border {{ border-left: 5px solid var(--critical); }}
        .severity-high-border {{ border-left: 5px solid var(--high); }}
        .severity-medium-border {{ border-left: 5px solid var(--medium); }}
        .severity-low-border {{ border-left: 5px solid var(--low); }}
        .severity-info-border {{ border-left: 5px solid var(--info); }}

        .tech-pill {{
            display: inline-block;
            background-color: #e2e8f0;
            color: var(--primary);
            padding: 0.35rem 0.75rem;
            border-radius: 50px;
            font-size: 0.85rem;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }}

        .finding-card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            scroll-margin-top: 20px;
        }}

        .finding-card-header {{
            padding: 1rem 1.5rem;
            background-color: #f8fafc;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .finding-card-header h3 {{
            margin: 0;
            font-size: 1.15rem;
            flex-grow: 1;
            margin-left: 1rem;
        }}

        .finding-id {{
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .finding-card-body {{
            padding: 1.5rem;
        }}

        table.table-compact {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.5rem;
        }}

        table.table-compact th, table.table-compact td {{
            padding: 0.5rem;
            border: 1px solid var(--border);
            font-size: 0.85rem;
            text-align: left;
        }}

        table.table-compact th {{
            background-color: #f8fafc;
            width: 20%;
            color: var(--text-muted);
        }}

        table.table-compact td {{
            width: 30%;
        }}

        .section-sub h4 {{
            margin-top: 1.5rem;
            margin-bottom: 0.5rem;
            font-size: 0.95rem;
            color: var(--primary);
            border-bottom: 1px solid #f1f5f9;
            padding-bottom: 0.25rem;
        }}

        .section-sub p {{
            margin: 0;
            font-size: 0.9rem;
            color: var(--text);
        }}

        .evidence-block {{
            background-color: #0f172a;
            color: #38bdf8;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.85rem;
            margin: 0;
        }}

        .text-muted {{ color: var(--text-muted); }}
        .no-findings {{
            text-align: center;
            padding: 3rem;
            background-color: #fff;
            border: 1px dashed var(--border);
            border-radius: 8px;
            color: var(--text-muted);
        }}
        
        .footer-notice {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 3rem;
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
            text-align: center;
        }}

        .distribution-chart {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            margin-top: 1rem;
        }}

        .chart-row {{
            display: flex;
            align-items: center;
            font-size: 0.85rem;
        }}

        .chart-label {{
            width: 80px;
            font-weight: 600;
        }}

        .chart-bar-container {{
            flex-grow: 1;
            background-color: #f1f5f9;
            height: 12px;
            border-radius: 4px;
            overflow: hidden;
            margin: 0 10px;
        }}

        .chart-bar {{
            height: 100%;
            border-radius: 4px;
        }}

        .chart-value {{
            width: 25px;
            text-align: right;
            font-weight: bold;
        }}
    </style>
</head>
<body>

    <header>
        <div class="grid-header" style="max-width: 1200px; margin: 0 auto;">
            <div class="title-block">
                <h1>WebReconX</h1>
                <p>Web Application Reconnaissance & Security Assessment Report (v{self.data.get('scanner_version')})</p>
            </div>
            <div class="risk-badge-large {risk_color_class}">
                <div>Overall Risk Score</div>
                <span>{self.data.get('risk_score')} / 10 ({risk_level})</span>
            </div>
        </div>
    </header>

    <div class="container">
        
        <div class="grid-layout">
            <div>
                <!-- Executive Summary -->
                <div class="card">
                    <h2>Executive Summary</h2>
                    <p>
                        A security assessment was performed against <strong>{self.data.get('target')}</strong> using the WebReconX security assessment framework.
                        The scan crawled <strong>{self.data.get('pages_discovered')}</strong> pages, scanning <strong>{self.data.get('pages_scanned')}</strong> under the <strong>{self.data.get('scan_mode')}</strong> target validation constraints.
                        A total of <strong>{len(self.findings)}</strong> configuration exposures or vulnerabilities were identified. 
                        The calculated peak risk score is <strong>{self.data.get('risk_score')} / 10</strong>, denoting a <strong>{risk_level}</strong> risk level.
                    </p>
                </div>

                <!-- Reconnaissance & Technology Stack -->
                <div class="card">
                    <h2>Reconnaissance & Technology Stack</h2>
                    <table class="table-report">
                        <tr>
                            <th>Root Domain / Target</th>
                            <td><code>{self.data.get('target')}</code></td>
                        </tr>
                        <tr>
                            <th>Identified Technologies</th>
                            <td>{tech_html}</td>
                        </tr>
                        <tr>
                            <th>Robots.txt Details</th>
                            <td>{robots_status}</td>
                        </tr>
                        <tr>
                            <th>Sitemap.xml Details</th>
                            <td>{sitemap_status}</td>
                        </tr>
                        <tr>
                            <th>Scan Duration</th>
                            <td>{self.data.get('duration_seconds')} seconds</td>
                        </tr>
                    </table>
                </div>

                <!-- Findings Table -->
                <div class="card">
                    <h2>Identified Vulnerabilities & Exposures</h2>
                    <table class="table-report">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Finding ID</th>
                                <th>Title</th>
                                <th>OWASP Category</th>
                                <th>Affected URL</th>
                            </tr>
                        </thead>
                        <tbody>
                            {findings_table_html}
                        </tbody>
                    </table>
                </div>

                <!-- Detailed Findings -->
                <h2>Detailed Vulnerability Summary</h2>
                {findings_details_html}
                
            </div>

            <!-- Sidebar -->
            <div>
                <!-- Scan Details Card -->
                <div class="card">
                    <h2>Scan Specifications</h2>
                    <p style="font-size: 0.85rem; margin: 0 0 0.5rem 0;"><strong>Scan ID:</strong> <br><code style="font-size: 0.75rem;">{self.data.get('scan_id')}</code></p>
                    <p style="font-size: 0.85rem; margin: 0 0 0.5rem 0;"><strong>Start Time:</strong> <br><span class="text-muted">{self.data.get('start_time')}</span></p>
                    <p style="font-size: 0.85rem; margin: 0 0 0.5rem 0;"><strong>End Time:</strong> <br><span class="text-muted">{self.data.get('end_time')}</span></p>
                    <p style="font-size: 0.85rem; margin: 0 0 0.5rem 0;"><strong>Scan Mode:</strong> <br><span class="badge {risk_color_class}">{self.data.get('scan_mode')}</span></p>
                </div>

                <!-- Severity Distribution Chart -->
                <div class="card">
                    <h2>Severity Density</h2>
                    <div class="distribution-chart">
                        <div class="chart-row">
                            <span class="chart-label">Critical</span>
                            <div class="chart-bar-container">
                                <div class="chart-bar severity-critical" style="width: {min(100, (self.data.get('severity_distribution', {}).get('CRITICAL', 0) / max(1, len(self.findings))) * 100)}%;"></div>
                            </div>
                            <span class="chart-value">{self.data.get('severity_distribution', {}).get('CRITICAL', 0)}</span>
                        </div>
                        <div class="chart-row">
                            <span class="chart-label">High</span>
                            <div class="chart-bar-container">
                                <div class="chart-bar severity-high" style="width: {min(100, (self.data.get('severity_distribution', {}).get('HIGH', 0) / max(1, len(self.findings))) * 100)}%;"></div>
                            </div>
                            <span class="chart-value">{self.data.get('severity_distribution', {}).get('HIGH', 0)}</span>
                        </div>
                        <div class="chart-row">
                            <span class="chart-label">Medium</span>
                            <div class="chart-bar-container">
                                <div class="chart-bar severity-medium" style="width: {min(100, (self.data.get('severity_distribution', {}).get('MEDIUM', 0) / max(1, len(self.findings))) * 100)}%;"></div>
                            </div>
                            <span class="chart-value">{self.data.get('severity_distribution', {}).get('MEDIUM', 0)}</span>
                        </div>
                        <div class="chart-row">
                            <span class="chart-label">Low</span>
                            <div class="chart-bar-container">
                                <div class="chart-bar severity-low" style="width: {min(100, (self.data.get('severity_distribution', {}).get('LOW', 0) / max(1, len(self.findings))) * 100)}%;"></div>
                            </div>
                            <span class="chart-value">{self.data.get('severity_distribution', {}).get('LOW', 0)}</span>
                        </div>
                        <div class="chart-row">
                            <span class="chart-label">Info</span>
                            <div class="chart-bar-container">
                                <div class="chart-bar severity-info" style="width: {min(100, (self.data.get('severity_distribution', {}).get('INFO', 0) / max(1, len(self.findings))) * 100)}%;"></div>
                            </div>
                            <span class="chart-value">{self.data.get('severity_distribution', {}).get('INFO', 0)}</span>
                        </div>
                    </div>
                </div>
                
                <!-- Legal Notice -->
                <div class="card">
                    <h2>Testing Disclaimer</h2>
                    <p style="font-size: 0.8rem; margin: 0; color: var(--text-muted);">
                        This report was generated by WebReconX in accordance with authorized local penetration testing standards. 
                        Testing must strictly occur on endpoints under direct ownership or with explicit digital authorization.
                        Passive mode contains solely non-intrusive metadata reviews.
                    </p>
                </div>
            </div>
        </div>

        <div class="footer-notice">
            WebReconX framework v{self.data.get('scanner_version')} | Derived from web-app-security-scanner (MIT License) | Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </div>
    </div>

</body>
</html>
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_template)
