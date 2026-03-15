"""
Module: Directory Bruteforce Scanner
======================================
Purpose:
    Discovers hidden or unlinked directories and files on a web server
    by trying common path names from a wordlist. Exposed admin panels,
    backup files, and configuration endpoints are a major security risk.

Logic:
    1. Load a wordlist of common directory/file names.
    2. For each entry, construct a full URL and send an HTTP GET request.
    3. If the server returns HTTP 200/301/302/403, the path likely exists.
    4. Use threading to speed up the scan significantly.
    5. Return all discovered paths with their status codes.

OWASP Reference:
    https://owasp.org/www-community/attacks/Forced_browsing
"""

import requests
import threading
from queue import Queue
from colorama import Fore, Style


# HTTP status codes that indicate a path exists
INTERESTING_CODES = {
    200: ("FOUND",    Fore.GREEN),
    301: ("REDIRECT", Fore.CYAN),
    302: ("REDIRECT", Fore.CYAN),
    403: ("FORBIDDEN — exists but protected", Fore.YELLOW),
    401: ("UNAUTHORIZED — auth required",     Fore.YELLOW),
    500: ("SERVER ERROR — worth noting",       Fore.RED),
}


class DirectoryScanner:
    """
    Multi-threaded directory and file bruteforce scanner.
    Uses a queue-based thread pool for efficient scanning.
    """

    def __init__(self, url: str, wordlist: str = "wordlists/directories.txt",
                 timeout: int = 10, threads: int = 10):
        self.url = url.rstrip("/")
        self.wordlist_path = wordlist
        self.timeout = timeout
        self.thread_count = threads

        self.queue = Queue()          # Thread-safe work queue
        self.found = []               # Discovered paths (shared, lock-protected)
        self.lock = threading.Lock()  # Prevents race conditions on self.found
        self.results = {
            "found_paths": [],
            "total_tested": 0,
            "wordlist": wordlist,
        }

    def _load_wordlist(self) -> list:
        """Read the wordlist file and return non-empty, non-comment lines."""
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            print(f"  {Fore.GREEN}[✔] Loaded {len(words)} entries from {self.wordlist_path}{Style.RESET_ALL}")
            return words
        except FileNotFoundError:
            print(f"  {Fore.RED}[✘] Wordlist not found: {self.wordlist_path}{Style.RESET_ALL}")
            return []

    def _scan_worker(self):
        """Worker thread: pulls paths from queue and tests each one."""
        headers = {"User-Agent": "Mozilla/5.0 (MiniVulnScanner/1.0)"}

        while not self.queue.empty():
            path = self.queue.get()
            target = f"{self.url}/{path}"

            try:
                resp = requests.get(
                    target,
                    timeout=self.timeout,
                    allow_redirects=False,  # Don't follow; we want the raw code
                    headers=headers,
                )
                code = resp.status_code

                if code in INTERESTING_CODES:
                    label, color = INTERESTING_CODES[code]
                    entry = {
                        "path": target,
                        "status": code,
                        "label": label,
                        "size": len(resp.content),
                    }

                    # Thread-safe append to shared list
                    with self.lock:
                        self.found.append(entry)

                    print(
                        f"  {color}[{code}] {label:<35} {Fore.WHITE}{target}{Style.RESET_ALL}"
                    )

            except requests.exceptions.ConnectionError:
                pass  # Server refused — path doesn't exist
            except requests.exceptions.Timeout:
                pass  # Timed out — skip silently
            finally:
                self.queue.task_done()

    def run(self) -> dict:
        """Load wordlist, spin up threads, and return discovered paths."""
        print(f"  {Fore.CYAN}[*] Target   : {self.url}")
        print(f"  {Fore.CYAN}[*] Threads  : {self.thread_count}")
        print(f"  {Fore.CYAN}[*] Timeout  : {self.timeout}s{Style.RESET_ALL}\n")

        words = self._load_wordlist()
        if not words:
            return self.results

        self.results["total_tested"] = len(words)

        # Populate the thread-safe queue
        for word in words:
            self.queue.put(word)

        print(f"  {Fore.YELLOW}[~] Scanning... (this may take a moment){Style.RESET_ALL}\n")

        # Create and start worker threads
        threads = []
        for _ in range(min(self.thread_count, len(words))):
            t = threading.Thread(target=self._scan_worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait for all threads to finish
        for t in threads:
            t.join()

        self.results["found_paths"] = self.found

        # ── Summary
        print(f"\n  {Fore.WHITE}{'─' * 50}")
        print(f"  {Fore.GREEN}Tested  : {len(words)} paths")
        print(f"  {Fore.YELLOW}Found   : {len(self.found)} interesting paths{Style.RESET_ALL}")

        return self.results
