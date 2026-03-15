#!/usr/bin/env python3
"""
Mini Web Vulnerability Scanner
================================
A modular, command-line web security testing tool for educational purposes.
Author: Your Name
License: MIT
"""

import argparse
import sys
import os
import time
from datetime import datetime
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Import scanner modules
from modules.header_scan import SecurityHeaderScanner
from modules.dir_scan import DirectoryScanner
from modules.sqli_test import SQLiTester
from modules.xss_test import XSSTester
from modules.report_gen import ReportGenerator


# ─────────────────────────────────────────────
#  ASCII Banner
# ─────────────────────────────────────────────

BANNER = f"""
{Fore.RED}
  ███╗   ███╗██╗███╗   ██╗██╗    ██╗███████╗██████╗ 
  ████╗ ████║██║████╗  ██║██║    ██║██╔════╝██╔══██╗
  ██╔████╔██║██║██╔██╗ ██║██║ █╗ ██║█████╗  ██████╔╝
  ██║╚██╔╝██║██║██║╚██╗██║██║███╗██║██╔══╝  ██╔══██╗
  ██║ ╚═╝ ██║██║██║ ╚████║╚███╔███╔╝███████╗██████╔╝
  ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝ ╚══╝╚══╝ ╚══════╝╚═════╝ 
{Style.RESET_ALL}
{Fore.YELLOW}  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ {Style.RESET_ALL}
{Fore.CYAN}       Mini Web Vulnerability Scanner v1.0{Style.RESET_ALL}
{Fore.WHITE}       For educational and authorized testing only{Style.RESET_ALL}
{Fore.RED}       ⚠  Use only against systems you own or have permission to test  ⚠{Style.RESET_ALL}
"""


def print_banner():
    print(BANNER)


def print_section(title: str):
    """Print a formatted section header."""
    width = 60
    print(f"\n{Fore.CYAN}{'─' * width}")
    print(f"  {Fore.YELLOW}▶  {Fore.WHITE}{title}")
    print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")


def validate_url(url: str) -> str:
    """Ensure URL has a proper scheme prefix."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def parse_arguments():
    """Configure and parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Mini Web Vulnerability Scanner — educational security testing tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scanner.py -u http://testphp.vulnweb.com --all\n"
            "  python scanner.py -u http://example.com --headers --sqli\n"
            "  python scanner.py -u http://example.com --dir --wordlist wordlists/directories.txt\n"
        ),
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL (e.g. http://example.com)"
    )

    # Module selection flags
    parser.add_argument("--headers",  action="store_true", help="Run Security Header Scanner")
    parser.add_argument("--dir",      action="store_true", help="Run Directory Bruteforce Scanner")
    parser.add_argument("--sqli",     action="store_true", help="Run SQL Injection Tester")
    parser.add_argument("--xss",      action="store_true", help="Run XSS Payload Tester")
    parser.add_argument("--all",      action="store_true", help="Run ALL scanner modules")

    # Options
    parser.add_argument(
        "--wordlist",
        default="wordlists/directories.txt",
        help="Path to wordlist file for directory bruteforce (default: wordlists/directories.txt)"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output report filename (default: auto-generated in reports/)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads for directory scan (default: 10)"
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
#  Main Orchestrator
# ─────────────────────────────────────────────

def main():
    print_banner()

    args = parse_arguments()
    target_url = validate_url(args.url)

    # Collect all scan results for the final report
    scan_results = {
        "target": target_url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "headers": None,
        "directories": None,
        "sqli": None,
        "xss": None,
    }

    print(f"\n{Fore.GREEN}[✔] Target   : {Fore.WHITE}{target_url}")
    print(f"{Fore.GREEN}[✔] Started  : {Fore.WHITE}{scan_results['timestamp']}")
    print(f"{Fore.GREEN}[✔] Timeout  : {Fore.WHITE}{args.timeout}s")

    run_all = args.all

    # ── 1. Security Header Scanner ───────────────
    if run_all or args.headers:
        print_section("Security Header Scanner")
        scanner = SecurityHeaderScanner(target_url, timeout=args.timeout)
        scan_results["headers"] = scanner.run()

    # ── 2. Directory Bruteforce ──────────────────
    if run_all or args.dir:
        print_section("Directory Bruteforce Scanner")
        scanner = DirectoryScanner(
            target_url,
            wordlist=args.wordlist,
            timeout=args.timeout,
            threads=args.threads,
        )
        scan_results["directories"] = scanner.run()

    # ── 3. SQL Injection Tester ──────────────────
    if run_all or args.sqli:
        print_section("SQL Injection Tester")
        scanner = SQLiTester(target_url, timeout=args.timeout)
        scan_results["sqli"] = scanner.run()

    # ── 4. XSS Payload Tester ───────────────────
    if run_all or args.xss:
        print_section("XSS Payload Tester")
        scanner = XSSTester(target_url, timeout=args.timeout)
        scan_results["xss"] = scanner.run()

    # ── 5. Report Generator ──────────────────────
    print_section("Generating Report")
    report_gen = ReportGenerator(scan_results, output_path=args.output)
    report_path = report_gen.generate()

    print(f"\n{Fore.GREEN}{'═' * 60}")
    print(f"  {Fore.YELLOW}✔  Scan Complete!")
    print(f"  {Fore.WHITE}Report saved → {Fore.CYAN}{report_path}")
    print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
