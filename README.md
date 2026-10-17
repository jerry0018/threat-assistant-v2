# Threat Identification Assistant v2

Flask app that (1) looks up CVEs from the NVD API, (2) scans your own local network with nmap, and (3) exports findings as CSV or PDF.

**Use only on systems you own or have written permission to test.** Scans are restricted in code to loopback and private IPv4 ranges (/24 or smaller).

## Setup (Windows / macOS / Linux)
1. Install Python 3.10+ (https://python.org) and nmap (https://nmap.org/download). Reopen the terminal afterwards.
2. In VS Code open this folder, then open the terminal (Ctrl+`).
3. Create and activate a virtual environment:
   - Windows: `python -m venv venv` then `venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv venv` then `source venv/bin/activate`
4. `pip install -r requirements.txt`
5. Optional: get a free NVD API key (https://nvd.nist.gov/developers/request-an-api-key) and set `NVD_API_KEY`
   (Windows PowerShell: `$env:NVD_API_KEY="your-key"`; macOS/Linux: `export NVD_API_KEY=your-key`).
6. `python app.py` and open http://127.0.0.1:5000

## Try it
- CVE lookup: software `Apache HTTP Server`, version `2.4.49`.
- Scan: target `localhost` and tick the permission box. Safe practice: run OWASP Juice Shop locally (Docker) and scan localhost.
- Add findings, then download CSV or PDF.

## How it works
| File | Job |
|---|---|
| `app.py` | Flask routes and input checks |
| `nvd.py` | NVD API call, 1-hour cache, rate-limit pause, CVSS parsing |
| `scanner.py` | Target allowlist, nmap run (no shell), XML parsing |
| `reports.py` | CSV (formula-safe) and PDF (ReportLab) |
| `static/` | Front end (HTML, CSS, JS) |

## Security notes
- nmap runs with an argument list, never a shell string, so input cannot inject commands.
- The front end writes data with `textContent` to avoid XSS.
- The server binds to 127.0.0.1 only. Do not expose it to the internet.

## Limitations
- NVD matching uses keyword search, so results can include false positives and misses.
- CVSS is severity, not your actual risk.
- Not included yet: OWASP ZAP web scanning, OSQuery endpoint checks, user accounts.

## Roadmap
1. Match CVEs using CPE names for better accuracy.
2. ZAP baseline scan against a local test app.
3. OSQuery checks on your own laptop.
4. Combine CVSS with asset importance for a risk rating.
