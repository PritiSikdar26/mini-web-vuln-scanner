# 🛡 Mini Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Security Tool](https://img.shields.io/badge/Type-Security%20Tool-red?style=flat-square)](#)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange?style=flat-square)](https://owasp.org)

> A modular, Python-based command-line web security testing tool for educational purposes.
> Performs automated checks for common vulnerabilities aligned with OWASP Top 10.

---

## ⚠️ Legal Disclaimer

> **This tool is for educational purposes and authorized security testing ONLY.**
> Never run this against websites or systems you do not own or have **explicit written permission** to test.
> Unauthorized scanning may be illegal under laws like the Computer Fraud and Abuse Act (CFAA).
> The author assumes no liability for misuse.

---

## 📋 Features

| Module | What It Does | OWASP Category |
|---|---|---|
| 🔍 **Header Scanner** | Checks for missing/misconfigured HTTP security headers | A05: Security Misconfiguration |
| 📁 **Directory Bruteforce** | Discovers hidden files, admin panels, backup paths | A01: Broken Access Control |
| 💉 **SQL Injection Tester** | Tests URL params for error-based & blind SQLi | A03: Injection |
| ⚡ **XSS Tester** | Tests inputs for reflected Cross-Site Scripting | A03: Injection |
| 📊 **Report Generator** | Produces HTML + JSON reports with risk scoring | — |

---

## 🗂 Project Structure

```
mini-web-vuln-scanner/
│
├── scanner.py              ← Main CLI entry point
│
├── modules/
│   ├── __init__.py
│   ├── header_scan.py      ← Security header checker
│   ├── dir_scan.py         ← Multi-threaded directory bruteforcer
│   ├── sqli_test.py        ← SQL injection payload tester
│   ├── xss_test.py         ← XSS payload tester
│   └── report_gen.py       ← HTML/JSON report generator
│
├── wordlists/
│   └── directories.txt     ← 100+ common paths/files to probe
│
├── reports/                ← Auto-generated scan reports land here
├── screenshots/            ← Demo screenshots
│
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/mini-web-vuln-scanner.git
cd mini-web-vuln-scanner
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run a scan
```bash
# Run ALL modules against a target
python scanner.py -u http://testphp.vulnweb.com --all

# Run specific modules
python scanner.py -u http://example.com --headers --sqli

# Directory bruteforce with custom wordlist
python scanner.py -u http://example.com --dir --wordlist wordlists/directories.txt

# Full options
python scanner.py -u http://example.com --all --threads 20 --timeout 15
```

---

## 🖥 Usage & CLI Reference

```
usage: scanner.py [-h] -u URL [--headers] [--dir] [--sqli] [--xss] [--all]
                  [--wordlist WORDLIST] [--output OUTPUT]
                  [--timeout TIMEOUT] [--threads THREADS]

Mini Web Vulnerability Scanner — educational security testing tool

required arguments:
  -u URL, --url URL       Target URL (e.g. http://example.com)

scanner modules:
  --headers               Run Security Header Scanner
  --dir                   Run Directory Bruteforce Scanner
  --sqli                  Run SQL Injection Tester
  --xss                   Run XSS Payload Tester
  --all                   Run ALL scanner modules

options:
  --wordlist WORDLIST      Path to wordlist (default: wordlists/directories.txt)
  --output OUTPUT          Custom report filename
  --timeout TIMEOUT        HTTP timeout in seconds (default: 10)
  --threads THREADS        Threads for directory scan (default: 10)
```

---

## 📸 Sample Output

```
  ███╗   ███╗██╗███╗   ██╗██╗    ██╗███████╗██████╗
  ...
       Mini Web Vulnerability Scanner v1.0
       For educational and authorized testing only

[✔] Target   : http://testphp.vulnweb.com
[✔] Started  : 2024-01-15 14:32:01

──────────────────────────────────────────────────────
  ▶  Security Header Scanner
──────────────────────────────────────────────────────
  [✘] MISSING  Content-Security-Policy            Risk: HIGH
  [✘] MISSING  Strict-Transport-Security          Risk: HIGH
  [✔] PRESENT  X-Content-Type-Options             nosniff
  [!] INFO LEAK  Server                 Apache/2.4.7

──────────────────────────────────────────────────────
  ▶  SQL Injection Tester
──────────────────────────────────────────────────────
  [→] Testing parameter: 'id'
    [!] POSSIBLE SQLi! Param='id' → DB error: 'mysql_fetch'
```

---

## 📊 Sample HTML Report

The scanner auto-generates a color-coded HTML report in the `reports/` directory after each scan. The report includes:

- **Risk Score** (0–100) with CRITICAL / HIGH / MEDIUM / LOW classification
- Security header audit table
- Discovered directories table
- SQLi and XSS findings
- Remediation recommendations

---

## 🧪 Safe Testing Targets

**Only test against systems you own or have permission to test. These legal practice targets are designed for learning:**

| Target | URL | Notes |
|---|---|---|
| DVWA | `http://localhost/dvwa` | Run locally with Docker |
| Vulnweb | `http://testphp.vulnweb.com` | Acunetix's test site |
| HackTheBox | `https://hackthebox.com` | Legal CTF environment |
| TryHackMe | `https://tryhackme.com` | Legal CTF environment |
| WebGoat | `http://localhost:8080/WebGoat` | OWASP's training app |

---

## 🏗 Architecture Overview

```
scanner.py (CLI Orchestrator)
     │
     ├── SecurityHeaderScanner   → requests → HTTP headers → compare vs allowlist
     ├── DirectoryScanner        → Queue + ThreadPool → HTTP GET → status codes
     ├── SQLiTester              → payload injection → error/time-based detection
     ├── XSSTester               → payload injection → reflection detection
     └── ReportGenerator         → aggregate results → HTML + JSON output
```

---

## 🛠 Tech Stack

- **Language**: Python 3.8+
- **HTTP**: `requests` — HTTP client for all web interactions
- **Parsing**: `beautifulsoup4` — HTML parsing for form discovery
- **CLI Colors**: `colorama` — Cross-platform terminal color support
- **Concurrency**: `threading` + `queue` — Multi-threaded directory scanning
- **Reports**: Pure Python — HTML/JSON report generation

---

## 🔒 How Each Module Works

### Security Header Scanner
Fetches HTTP headers via GET request and compares against 8 critical security headers defined by OWASP Secure Headers Project. Reports missing headers with risk levels (HIGH/MEDIUM/LOW) and detects information-leaking headers like `Server` and `X-Powered-By`.

### Directory Bruteforce Scanner
Loads a wordlist and uses a thread-safe `Queue` + thread pool to concurrently probe each path. Flags responses with status codes 200, 301, 302, 403, 401, and 500 as interesting. Threads configurable via `--threads`.

### SQL Injection Tester
Extracts URL query parameters (or discovers form inputs via BeautifulSoup). For each parameter, injects 10+ error-based payloads and checks response body against 20+ database error signatures. Also performs time-based blind SQLi detection by measuring response delays.

### XSS Payload Tester
Tests URL parameters and HTML form fields with 12 XSS payloads covering basic injection, event handlers, attribute escaping, and filter evasion. Checks if the payload appears unescaped in the response HTML (reflected XSS detection).

---

## 📈 Roadmap / Future Features

- [ ] Subdomain enumeration module
- [ ] CSRF token detection
- [ ] Open redirect tester
- [ ] Stored XSS detection
- [ ] Cookie security analyzer (HttpOnly, Secure, SameSite)
- [ ] SSL/TLS certificate checker
- [ ] PDF report export
- [ ] Rate limiting / polite scanning delays

---

## 🤝 Contributing

Pull requests welcome! Please:
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Add tests or sample output
4. Submit a PR with a clear description

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Priti Sikdar**
- GitHub: [@PritiSikdar26](https://github.com/PritiSikdar26)
- LinkedIn: [Priti Sikdar](https://www.linkedin.com/in/priti-sikdar-744399239/)

---

*Built for educational purposes as part of a cybersecurity portfolio project.*
