"""
Module: Report Generator
==========================
Purpose:
    Aggregates all scan results and generates a professional HTML report
    with color-coded findings, a summary dashboard, and remediation advice.

Logic:
    1. Accept the complete results dictionary from all scanner modules.
    2. Build a structured HTML report with:
       - Executive summary / risk score
       - Per-module findings
       - Remediation guidance
    3. Save the report to the /reports directory.
    4. Also save a plain-text summary for quick review.
"""

import os
import json
from datetime import datetime
from colorama import Fore, Style


class ReportGenerator:
    """Generates HTML and plain-text reports from scanner results."""

    def __init__(self, results: dict, output_path: str = None):
        self.results = results
        self.timestamp = results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.target = results.get("target", "Unknown")

        # Auto-generate filename if not provided
        if output_path is None:
            safe_host = self.target.replace("http://", "").replace("https://", "").replace("/", "_").replace("?", "_").replace("=", "_").replace("&", "_").replace(":", "_").replace("*", "_").replace("|", "_").replace("<", "_").replace(">", "_").replace('"', "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_path = os.path.join("reports", f"scan_{safe_host}_{ts}.html")
        else:
            self.output_path = output_path

        os.makedirs("reports", exist_ok=True)

    # ─────────────────────────────────────────
    #  Risk Scoring
    # ─────────────────────────────────────────

    def _calculate_risk_score(self) -> tuple:
        """
        Calculate an overall risk score (0-100) based on findings.
        Returns (score, risk_label, color).
        """
        score = 0
        max_score = 100

        headers = self.results.get("headers")
        if headers:
            missing = headers.get("missing", [])
            for m in missing:
                if m["risk"] == "HIGH":
                    score += 10
                elif m["risk"] == "MEDIUM":
                    score += 5
                else:
                    score += 2
            score += len(headers.get("info_leaks", [])) * 3

        dirs = self.results.get("directories")
        if dirs:
            score += len(dirs.get("found_paths", [])) * 4

        sqli = self.results.get("sqli")
        if sqli and sqli.get("vulnerable_params"):
            score += len(sqli["vulnerable_params"]) * 20

        xss = self.results.get("xss")
        if xss and xss.get("vulnerable_inputs"):
            score += len(xss["vulnerable_inputs"]) * 15

        score = min(score, max_score)

        if score >= 70:
            label, color = "CRITICAL", "#e74c3c"
        elif score >= 45:
            label, color = "HIGH", "#e67e22"
        elif score >= 20:
            label, color = "MEDIUM", "#f1c40f"
        else:
            label, color = "LOW", "#2ecc71"

        return score, label, color

    # ─────────────────────────────────────────
    #  HTML Report
    # ─────────────────────────────────────────

    def _build_html(self) -> str:
        """Build the complete HTML report string."""
        score, risk_label, risk_color = self._calculate_risk_score()

        header_rows = self._build_header_rows()
        dir_rows = self._build_dir_rows()
        sqli_rows = self._build_sqli_rows()
        xss_rows = self._build_xss_rows()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Scan Report — {self.target}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --muted: #8b949e;
      --accent: #58a6ff;
      --green: #3fb950;
      --yellow: #d29922;
      --red: #f85149;
      --orange: #e67e22;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 2rem;
      line-height: 1.6;
    }}
    h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 0.25rem; }}
    h2 {{ font-size: 1.2rem; color: var(--accent); margin: 1.5rem 0 0.75rem; border-left: 3px solid var(--accent); padding-left: 0.75rem; }}
    .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }}
    .dashboard {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      flex: 1;
      min-width: 160px;
    }}
    .card .label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }}
    .card .value {{ font-size: 1.8rem; font-weight: 700; margin-top: 0.2rem; }}
    .risk-score {{ font-size: 3rem !important; color: {risk_color}; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.9rem; }}
    th {{ background: var(--surface); color: var(--muted); font-weight: 600; text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); }}
    td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .badge-high    {{ background: #3d1a1a; color: var(--red); }}
    .badge-medium  {{ background: #2d2000; color: var(--yellow); }}
    .badge-low     {{ background: #1a2d1a; color: var(--green); }}
    .badge-found   {{ background: #1a2d1a; color: var(--green); }}
    .badge-missing {{ background: #3d1a1a; color: var(--red); }}
    .badge-vuln    {{ background: #3d1a1a; color: var(--red); }}
    .badge-safe    {{ background: #1a2d1a; color: var(--green); }}
    .code {{ font-family: 'Consolas', monospace; font-size: 0.82rem; background: #0d1117; padding: 0.1rem 0.4rem; border-radius: 3px; word-break: break-all; }}
    section {{ margin-bottom: 2.5rem; }}
    .remediation {{ background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--yellow); border-radius: 6px; padding: 1rem 1.25rem; margin-top: 2rem; }}
    .remediation h3 {{ color: var(--yellow); margin-bottom: 0.5rem; }}
    .remediation ul {{ padding-left: 1.25rem; color: var(--muted); }}
    .remediation li {{ margin-bottom: 0.4rem; }}
    footer {{ text-align: center; margin-top: 3rem; color: var(--muted); font-size: 0.8rem; }}
  </style>
</head>
<body>

  <h1>🛡 Mini Web Vulnerability Scanner — Scan Report</h1>
  <p class="meta">
    Target: <strong>{self.target}</strong> &nbsp;|&nbsp;
    Scan Date: <strong>{self.timestamp}</strong> &nbsp;|&nbsp;
    Generated by: <strong>Mini Web Vulnerability Scanner v1.0</strong>
  </p>

  <!-- ── Dashboard ── -->
  <div class="dashboard">
    <div class="card">
      <div class="label">Risk Score</div>
      <div class="value risk-score">{score}</div>
    </div>
    <div class="card">
      <div class="label">Risk Level</div>
      <div class="value" style="color:{risk_color}">{risk_label}</div>
    </div>
    <div class="card">
      <div class="label">Missing Headers</div>
      <div class="value" style="color:var(--red)">{len(self.results.get('headers', {}).get('missing', []) if self.results.get('headers') else [])}</div>
    </div>
    <div class="card">
      <div class="label">Dirs Found</div>
      <div class="value" style="color:var(--yellow)">{len(self.results.get('directories', {}).get('found_paths', []) if self.results.get('directories') else [])}</div>
    </div>
    <div class="card">
      <div class="label">SQLi Findings</div>
      <div class="value" style="color:var(--red)">{len(self.results.get('sqli', {}).get('vulnerable_params', []) if self.results.get('sqli') else [])}</div>
    </div>
    <div class="card">
      <div class="label">XSS Findings</div>
      <div class="value" style="color:var(--red)">{len(self.results.get('xss', {}).get('vulnerable_inputs', []) if self.results.get('xss') else [])}</div>
    </div>
  </div>

  <!-- ── Section 1: Headers ── -->
  <section>
    <h2>1. Security Header Analysis</h2>
    {header_rows}
  </section>

  <!-- ── Section 2: Directories ── -->
  <section>
    <h2>2. Directory Bruteforce Results</h2>
    {dir_rows}
  </section>

  <!-- ── Section 3: SQLi ── -->
  <section>
    <h2>3. SQL Injection Test Results</h2>
    {sqli_rows}
  </section>

  <!-- ── Section 4: XSS ── -->
  <section>
    <h2>4. XSS Test Results</h2>
    {xss_rows}
  </section>

  <!-- ── Remediation ── -->
  <div class="remediation">
    <h3>⚡ Remediation Recommendations</h3>
    <ul>
      <li><strong>Security Headers:</strong> Implement Content-Security-Policy, Strict-Transport-Security, and X-Frame-Options on your web server or reverse proxy.</li>
      <li><strong>SQL Injection:</strong> Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.</li>
      <li><strong>XSS:</strong> Encode all user-supplied data before rendering in HTML. Use a strict Content-Security-Policy to limit script execution.</li>
      <li><strong>Directory Exposure:</strong> Disable directory listing, remove backup files, and restrict access to sensitive paths via your web server config.</li>
      <li><strong>Info Leaks:</strong> Remove or obfuscate Server and X-Powered-By headers to avoid fingerprinting.</li>
    </ul>
  </div>

  <footer>
    ⚠ This report is for educational and authorized testing purposes only. &nbsp;|&nbsp; Mini Web Vulnerability Scanner v1.0
  </footer>

</body>
</html>"""

    def _build_header_rows(self) -> str:
        headers = self.results.get("headers")
        if not headers:
            return "<p style='color:var(--muted)'>Header scan not run.</p>"

        rows = ""
        for h in headers.get("present", []):
            rows += f"""<tr>
              <td><span class="badge badge-found">PRESENT</span></td>
              <td>{h['header']}</td>
              <td><span class="code">{h['value'][:80]}</span></td>
              <td><span class="badge badge-{h['risk'].lower()}">{h['risk']}</span></td>
            </tr>"""
        for h in headers.get("missing", []):
            rows += f"""<tr>
              <td><span class="badge badge-missing">MISSING</span></td>
              <td>{h['header']}</td>
              <td style="color:var(--muted)">{h['description']}</td>
              <td><span class="badge badge-{h['risk'].lower()}">{h['risk']}</span></td>
            </tr>"""

        return f"""<table>
          <thead><tr><th>Status</th><th>Header</th><th>Value / Note</th><th>Risk</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _build_dir_rows(self) -> str:
        dirs = self.results.get("directories")
        if not dirs:
            return "<p style='color:var(--muted)'>Directory scan not run.</p>"
        paths = dirs.get("found_paths", [])
        if not paths:
            return f"<p style='color:var(--muted)'>Tested {dirs.get('total_tested', 0)} paths — no interesting paths discovered.</p>"

        rows = "".join(f"""<tr>
          <td><span class="badge badge-found">{p['status']}</span></td>
          <td><span class="code">{p['path']}</span></td>
          <td>{p['label']}</td>
          <td>{p['size']} bytes</td>
        </tr>""" for p in paths)

        return f"""<table>
          <thead><tr><th>Code</th><th>Path</th><th>Note</th><th>Size</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _build_sqli_rows(self) -> str:
        sqli = self.results.get("sqli")
        if not sqli:
            return "<p style='color:var(--muted)'>SQLi scan not run.</p>"
        vulns = sqli.get("vulnerable_params", [])
        if not vulns:
            return f"<p style='color:var(--green)'>✔ No SQL injection vulnerabilities detected. ({len(sqli.get('tested_params', []))} param(s) tested)</p>"

        rows = "".join(f"""<tr>
          <td><span class="badge badge-vuln">VULNERABLE</span></td>
          <td><span class="code">{v['param']}</span></td>
          <td>{'Error-based' if v['error_based'] else ''} {'Time-based' if v['time_based'] else ''}</td>
        </tr>""" for v in vulns)

        return f"""<table>
          <thead><tr><th>Status</th><th>Parameter</th><th>Type</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _build_xss_rows(self) -> str:
        xss = self.results.get("xss")
        if not xss:
            return "<p style='color:var(--muted)'>XSS scan not run.</p>"
        vulns = xss.get("vulnerable_inputs", [])
        if not vulns:
            return f"<p style='color:var(--green)'>✔ No reflected XSS vulnerabilities detected.</p>"

        rows = "".join(f"""<tr>
          <td><span class="badge badge-vuln">VULNERABLE</span></td>
          <td>{v['type']}</td>
          <td><span class="code">{v['input']}</span></td>
          <td><span class="code">{v['payload'][:80]}</span></td>
        </tr>""" for v in vulns)

        return f"""<table>
          <thead><tr><th>Status</th><th>Type</th><th>Input</th><th>Payload</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    # ─────────────────────────────────────────
    #  Generate + Save
    # ─────────────────────────────────────────

    def generate(self) -> str:
        """Build and save the HTML report. Returns the file path."""
        html = self._build_html()

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  {Fore.GREEN}[✔] HTML report saved → {self.output_path}{Style.RESET_ALL}")

        # Also dump raw JSON for programmatic use
        json_path = self.output_path.replace(".html", ".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        print(f"  {Fore.CYAN}[✔] JSON data saved  → {json_path}{Style.RESET_ALL}")

        return self.output_path
