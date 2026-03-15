"""
Module: Security Header Scanner
================================
Purpose:
    Checks the HTTP response headers of a target URL against a list of
    security-critical headers. Missing or misconfigured headers are a
    common source of web vulnerabilities (clickjacking, MIME sniffing,
    XSS, etc.).

Logic:
    1. Send a GET request to the target.
    2. Compare the response headers against a known list of security headers.
    3. Flag headers that are missing or that contain known weak values.
    4. Return a structured results dict for the report generator.

OWASP Reference:
    https://owasp.org/www-project-secure-headers/
"""

import requests
from colorama import Fore, Style


# ─────────────────────────────────────────────
#  Expected Security Headers + explanations
# ─────────────────────────────────────────────

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks by controlling resource loading.",
        "risk": "HIGH",
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks by controlling iframe embedding.",
        "risk": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing which can lead to XSS.",
        "risk": "MEDIUM",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS), preventing protocol downgrade attacks.",
        "risk": "HIGH",
    },
    "Referrer-Policy": {
        "description": "Controls referrer info sent with requests to protect user privacy.",
        "risk": "LOW",
    },
    "Permissions-Policy": {
        "description": "Restricts browser features (camera, mic, geolocation, etc.).",
        "risk": "LOW",
    },
    "X-XSS-Protection": {
        "description": "Legacy browser XSS filter (still useful for older browsers).",
        "risk": "MEDIUM",
    },
    "Cache-Control": {
        "description": "Controls how pages are cached; prevents sensitive data caching.",
        "risk": "LOW",
    },
}

# Headers that expose server information (info leak)
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


class SecurityHeaderScanner:
    """Scans HTTP response headers for missing or insecure security headers."""

    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout
        self.results = {
            "present": [],
            "missing": [],
            "info_leaks": [],
            "raw_headers": {},
        }

    def _fetch_headers(self) -> dict:
        """Send a GET request and return the response headers."""
        try:
            response = requests.get(
                self.url,
                timeout=self.timeout,
                allow_redirects=True,
                # Mimic a real browser to avoid bot-blocking
                headers={"User-Agent": "Mozilla/5.0 (MiniVulnScanner/1.0)"},
            )
            return dict(response.headers)
        except requests.exceptions.ConnectionError:
            print(f"  {Fore.RED}[✘] Connection failed. Is the target reachable?{Style.RESET_ALL}")
            return {}
        except requests.exceptions.Timeout:
            print(f"  {Fore.RED}[✘] Request timed out after {self.timeout}s{Style.RESET_ALL}")
            return {}

    def _check_security_headers(self, headers: dict):
        """Compare response headers against the expected security header list."""
        # Normalize header names to lowercase for case-insensitive matching
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() in lower_headers:
                value = lower_headers[header.lower()]
                self.results["present"].append({
                    "header": header,
                    "value": value,
                    "risk": meta["risk"],
                    "description": meta["description"],
                })
                print(
                    f"  {Fore.GREEN}[✔] PRESENT  {Fore.WHITE}{header:<35}"
                    f"{Fore.CYAN}{value[:60]}{Style.RESET_ALL}"
                )
            else:
                self.results["missing"].append({
                    "header": header,
                    "risk": meta["risk"],
                    "description": meta["description"],
                })
                risk_color = Fore.RED if meta["risk"] == "HIGH" else Fore.YELLOW
                print(
                    f"  {Fore.RED}[✘] MISSING  {risk_color}{header:<35}"
                    f"{Fore.WHITE}Risk: {risk_color}{meta['risk']}{Style.RESET_ALL}"
                )

    def _check_info_leaks(self, headers: dict):
        """Detect headers that leak server/technology information."""
        lower_headers = {k.lower(): v for k, v in headers.items()}

        print(f"\n  {Fore.YELLOW}[~] Checking for information-leaking headers...{Style.RESET_ALL}")
        found_any = False

        for leak_header in INFO_LEAK_HEADERS:
            if leak_header.lower() in lower_headers:
                found_any = True
                value = lower_headers[leak_header.lower()]
                self.results["info_leaks"].append({
                    "header": leak_header,
                    "value": value,
                })
                print(
                    f"  {Fore.YELLOW}[!] INFO LEAK  {Fore.WHITE}{leak_header:<25}"
                    f"{Fore.YELLOW}{value}{Style.RESET_ALL}"
                )

        if not found_any:
            print(f"  {Fore.GREEN}[✔] No information-leaking headers detected.{Style.RESET_ALL}")

    def run(self) -> dict:
        """Execute the full header scan and return results."""
        print(f"  {Fore.CYAN}[*] Fetching headers from: {self.url}{Style.RESET_ALL}")

        headers = self._fetch_headers()
        if not headers:
            return self.results

        self.results["raw_headers"] = headers

        # ── Security header checks
        print(f"\n  {Fore.YELLOW}[~] Checking security headers ({len(SECURITY_HEADERS)} expected)...{Style.RESET_ALL}\n")
        self._check_security_headers(headers)

        # ── Information leak checks
        self._check_info_leaks(headers)

        # ── Summary
        present_count = len(self.results["present"])
        missing_count = len(self.results["missing"])
        score = int((present_count / len(SECURITY_HEADERS)) * 100)

        score_color = Fore.GREEN if score >= 70 else (Fore.YELLOW if score >= 40 else Fore.RED)

        print(f"\n  {Fore.WHITE}{'─' * 50}")
        print(f"  {Fore.GREEN}Present : {present_count}/{len(SECURITY_HEADERS)} headers")
        print(f"  {Fore.RED}Missing : {missing_count}/{len(SECURITY_HEADERS)} headers")
        print(f"  {score_color}Score   : {score}%{Style.RESET_ALL}")

        return self.results
