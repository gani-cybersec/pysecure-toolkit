import re
import socket
from datetime import datetime
from urllib.parse import urlparse

def _clean_domain(value):
    value = value.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0].strip().lower()
    if not value or "." not in value or re.search(r"\s", value):
        raise ValueError("Enter a valid domain, such as example.com.")
    return value

def analyze_domain(domain):
    try:
        domain = _clean_domain(domain)
    except ValueError as exc:
        return f"Input error: {exc}"

    lines = ["NETSENTRY — URL / DNS ANALYSIS", "=" * 54,
             f"Domain: {domain}", f"Time: {datetime.now():%Y-%m-%d %H:%M:%S}", ""]

    try:
        infos = socket.getaddrinfo(domain, None)
        ipv4 = sorted({x[4][0] for x in infos if x[0] == socket.AF_INET})
        ipv6 = sorted({x[4][0] for x in infos if x[0] == socket.AF_INET6})
    except socket.gaierror as exc:
        ipv4, ipv6 = [], []
        lines.append(f"Address lookup error: {exc}")

    lines.append("DNS ADDRESS RECORDS")
    lines.append("-" * 54)
    lines.append("A (IPv4): " + (", ".join(ipv4) if ipv4 else "No IPv4 address found"))
    lines.append("AAAA (IPv6): " + (", ".join(ipv6) if ipv6 else "No IPv6 address found"))

    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        ns_records = sorted(str(r.target).rstrip(".") for r in answers)
        lines.append("NS (Name Servers): " + ", ".join(ns_records))
    except ImportError:
        lines.append("NS records: Install dnspython to query NS records.")
    except Exception as exc:
        lines.append(f"NS records: Could not retrieve ({exc.__class__.__name__})")

    lines.extend(["", "WHOIS INFORMATION", "-" * 54])
    try:
        import whois
        data = whois.whois(domain)
        for label, key in [
            ("Registrar", "registrar"),
            ("Creation date", "creation_date"),
            ("Expiration date", "expiration_date"),
            ("Updated date", "updated_date"),
            ("Name servers", "name_servers"),
            ("Organization", "org"),
            ("Country", "country"),
        ]:
            value = data.get(key) if hasattr(data, "get") else None
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:5])
            lines.append(f"{label}: {value if value else 'Not available'}")
    except ImportError:
        lines.append("WHOIS unavailable: install python-whois.")
    except Exception as exc:
        lines.append(f"WHOIS lookup failed: {exc}")

    lines.extend(["", "Note: DNS and WHOIS data can be incomplete or privacy-protected."])
    return "\n".join(lines)
