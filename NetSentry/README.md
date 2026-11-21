# NetSentry

NetSentry is a Python desktop toolkit for basic, authorized security checks.

## Features
- TCP port scanner with concurrent workers and a simple exposure indicator.
- Domain analyzer for IPv4/IPv6 address lookups, NS records, and WHOIS.
- HTTP analyzer for status, redirects, HTTPS, security headers, cookie flags, and server headers.
- Tkinter graphical interface (included with most Python installations).

## Requirements
- Python 3.10 or newer
- Internet connection for DNS, WHOIS, and HTTP analysis
- Windows, macOS, or Linux

## Installation

Open a terminal in the NetSentry folder.

### Windows
```powershell
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
py main.py
```

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

## Usage
1. Open the Port Scanner tab and enter a host plus ports (for example `1-1024` or `22,80,443`).
2. Open URL / DNS Analyzer and enter a domain such as `example.com`.
3. Open HTTP Analyzer and enter a full URL such as `https://example.com`.

Only scan hosts and networks you own or have explicit permission to assess. Start with a small port range. The scanner performs TCP connection checks; it is not a stealth scanner or a full vulnerability scanner.

## Project structure
```text
NetSentry/
├── main.py
├── requirements.txt
├── README.md
└── modules/
    ├── __init__.py
    ├── port_scanner.py
    ├── url_analyzer.py
    └── http_analyzer.py
```

## Notes
- DNS NS lookup uses `dnspython`.
- WHOIS results may be rate-limited, privacy-protected, or unavailable.
- HTTP checks make a normal GET request and do not exploit vulnerabilities.
- Security scores are simple indicators for learning and triage, not professional audit ratings.
