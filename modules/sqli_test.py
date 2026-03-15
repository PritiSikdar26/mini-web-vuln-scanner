"""
Module: SQL Injection Tester
==============================
Purpose:
    Tests URL query parameters for basic SQL injection vulnerabilities.
    SQLi is consistently in OWASP's Top 10 and can lead to full database
    compromise, authentication bypass, and data exfiltration.

Logic:
    1. Parse the target URL to extract query parameters.
    2. If no parameters found, attempt to discover forms via BeautifulSoup.
    3. For each parameter, inject common SQLi payloads one at a time.
    4. Analyze the response for database error messages (error-based detection).
    5. Compare response times for time-based blind SQLi detection.
    6. Report potentially vulnerable parameters.

OWASP Reference:
    https://owasp.org/www-community/attacks/SQL_Injection

⚠ Disclaimer:
    This is an educational, surface-level detection tool. It does NOT
    perform actual exploitation. Use only on systems you own or have
    explicit written permission to test.
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from colorama import Fore, Style


# ─────────────────────────────────────────────
#  SQLi Payloads
# ─────────────────────────────────────────────

# Error-based payloads — trigger database error messages
ERROR_PAYLOADS = [
    "'",           # Single quote — most basic SQLi trigger
    "''",          # Double single quote
    "`",           # MySQL backtick
    "\"",          # Double quote
    "\\",          # Backslash
    "' OR '1'='1", # Classic auth bypass
    "' OR 1=1--",  # Comment-based bypass
    "' OR 1=1#",   # MySQL comment bypass
    "1' ORDER BY 1--",   # Column enumeration
    "1' UNION SELECT NULL--",  # UNION-based detection
]

# Time-based payloads — cause intentional server delays
TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",   # MSSQL time delay
    "' OR SLEEP(5)--",              # MySQL time delay
    "'; SELECT pg_sleep(5)--",      # PostgreSQL time delay
    "1 AND SLEEP(5)",               # Numeric context MySQL
]

# Strings that appear in database error messages
DB_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # MSSQL
    "unclosed quotation mark",
    "microsoft ole db provider",
    "odbc microsoft access",
    "syntax error converting",
    # Oracle
    "ora-01756",
    "ora-00933",
    "oracle error",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "postgresql",
    "syntax error at or near",
    # SQLite
    "sqlite_step",
    "sqlite error",
    # Generic
    "sql syntax",
    "sql error",
    "database error",
    "unclosed quotation",
]

# Time delay threshold — if response takes longer than this, flag as suspicious
TIME_THRESHOLD_SECONDS = 4.5


class SQLiTester:
    """Tests URL query parameters for SQL injection vulnerabilities."""

    def __init__(self, url: str, timeout: int = 15):
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (MiniVulnScanner/1.0)"})
        self.results = {
            "vulnerable_params": [],
            "tested_params": [],
            "forms_found": 0,
        }

    def _extract_params(self) -> dict:
        """Extract query parameters from the URL."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        # parse_qs gives lists; simplify to single values
        return {k: v[0] for k, v in params.items()}

    def _inject_payload(self, base_url: str, param: str, original_params: dict, payload: str) -> str:
        """Build a new URL with the payload injected into one parameter."""
        modified_params = original_params.copy()
        modified_params[param] = payload

        parsed = urlparse(base_url)
        new_query = urlencode(modified_params)
        injected_url = urlunparse(parsed._replace(query=new_query))
        return injected_url

    def _check_error_based(self, param: str, base_url: str, params: dict) -> bool:
        """
        Inject error-based payloads and look for database error signatures
        in the HTTP response body.
        """
        print(f"    {Fore.CYAN}[~] Error-based testing on param: '{param}'{Style.RESET_ALL}")

        for payload in ERROR_PAYLOADS:
            test_url = self._inject_payload(base_url, param, params, payload)
            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                body_lower = resp.text.lower()

                # Check for any known DB error signature in response
                for signature in DB_ERROR_SIGNATURES:
                    if signature in body_lower:
                        print(
                            f"    {Fore.RED}[!] POSSIBLE SQLi! Param='{param}' "
                            f"Payload='{payload}' → DB error: '{signature}'{Style.RESET_ALL}"
                        )
                        return True  # Stop after first hit per param

            except requests.exceptions.RequestException:
                pass

        return False

    def _check_time_based(self, param: str, base_url: str, params: dict) -> bool:
        """
        Inject time-delay payloads and measure response time. A significantly
        longer response suggests the SQL was executed.
        """
        print(f"    {Fore.CYAN}[~] Time-based blind testing on param: '{param}'{Style.RESET_ALL}")

        # Baseline: measure normal response time
        try:
            t0 = time.time()
            self.session.get(self.url, timeout=self.timeout)
            baseline = time.time() - t0
        except Exception:
            baseline = 1.0

        for payload in TIME_PAYLOADS:
            test_url = self._inject_payload(base_url, param, params, payload)
            try:
                t0 = time.time()
                self.session.get(test_url, timeout=self.timeout + 8)
                elapsed = time.time() - t0

                # If response took significantly longer than baseline, flag it
                if elapsed - baseline >= TIME_THRESHOLD_SECONDS:
                    print(
                        f"    {Fore.RED}[!] POSSIBLE Blind SQLi! Param='{param}' "
                        f"Response delayed by {elapsed - baseline:.1f}s{Style.RESET_ALL}"
                    )
                    return True

            except requests.exceptions.Timeout:
                # A timeout itself can indicate time-based SQLi
                print(
                    f"    {Fore.YELLOW}[!] Request timed out for param='{param}' "
                    f"(may indicate blind SQLi){Style.RESET_ALL}"
                )

        return False

    def _discover_forms(self) -> list:
        """
        Crawl the target page for HTML forms. Forms with GET/POST action
        and text inputs are candidates for SQLi testing.
        """
        forms = []
        try:
            resp = self.session.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                inputs = []

                for inp in form.find_all("input"):
                    inp_type = inp.get("type", "text")
                    inp_name = inp.get("name", "")
                    if inp_name and inp_type not in ("submit", "button", "hidden", "image"):
                        inputs.append(inp_name)

                if inputs:
                    forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                    })

        except Exception:
            pass

        return forms

    def run(self) -> dict:
        """Run all SQLi tests against detected parameters."""
        print(f"  {Fore.CYAN}[*] Target: {self.url}{Style.RESET_ALL}\n")

        params = self._extract_params()
        base_url = self.url.split("?")[0]

        if not params:
            print(f"  {Fore.YELLOW}[~] No query parameters in URL. Checking for HTML forms...{Style.RESET_ALL}")
            forms = self._discover_forms()
            self.results["forms_found"] = len(forms)

            if forms:
                print(f"  {Fore.GREEN}[✔] Found {len(forms)} form(s). Testing form inputs as params.{Style.RESET_ALL}")
                # Use first form's inputs as synthetic params for testing
                for form in forms:
                    params = {name: "test" for name in form["inputs"]}
                    break
            else:
                print(
                    f"  {Fore.YELLOW}[!] No testable parameters found. "
                    f"Try a URL like: {self.url}?id=1{Style.RESET_ALL}"
                )
                return self.results

        self.results["tested_params"] = list(params.keys())
        print(f"  {Fore.GREEN}[✔] Found {len(params)} parameter(s): {list(params.keys())}{Style.RESET_ALL}\n")

        for param in params:
            print(f"\n  {Fore.WHITE}[→] Testing parameter: {Fore.YELLOW}'{param}'{Style.RESET_ALL}")

            is_error_vuln = self._check_error_based(param, base_url, params)
            is_time_vuln  = self._check_time_based(param, base_url, params)

            if is_error_vuln or is_time_vuln:
                self.results["vulnerable_params"].append({
                    "param": param,
                    "error_based": is_error_vuln,
                    "time_based": is_time_vuln,
                })
            else:
                print(f"    {Fore.GREEN}[✔] No obvious SQLi detected for '{param}'{Style.RESET_ALL}")

        # ── Summary
        vuln_count = len(self.results["vulnerable_params"])
        print(f"\n  {Fore.WHITE}{'─' * 50}")
        print(f"  {Fore.CYAN}Params Tested : {len(params)}")
        if vuln_count:
            print(f"  {Fore.RED}Vulnerable    : {vuln_count} param(s) flagged{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}Vulnerable    : 0 (no obvious SQLi found){Style.RESET_ALL}")

        return self.results
