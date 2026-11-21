from urllib.parse import urlparse
import requests
from datetime import datetime

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS connections.",
    "Content-Security-Policy": "Helps reduce cross-site scripting and content injection risks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Helps protect against clickjacking.",
    "Referrer-Policy": "Controls referrer information sent by the browser.",
    "Permissions-Policy": "Restricts access to browser features."
}

def analyze_http(url):
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "Input error: Enter a complete URL beginning with http:// or https://"

    lines = ["NETSENTRY — HTTP SECURITY ANALYSIS", "=" * 54,
             f"URL: {url}", f"Time: {datetime.now():%Y-%m-%d %H:%M:%S}", ""]
    try:
        response = requests.get(
            url, timeout=12, allow_redirects=True,
            headers={"User-Agent": "NetSentry-Assessment/1.0"},
            verify=True
        )
        lines.extend([
            "CONNECTION",
            "-" * 54,
            f"Final URL: {response.url}",
            f"HTTP status: {response.status_code} {response.reason}",
            f"HTTPS used: {'Yes' if response.url.lower().startswith('https://') else 'No'}",
            f"Redirect count: {len(response.history)}",
            f"Content type: {response.headers.get('Content-Type', 'Not provided')}",
            "",
            "REDIRECT CHAIN",
            "-" * 54
        ])
        if response.history:
            for index, old in enumerate(response.history, 1):
                lines.append(f"{index}. {old.status_code} -> {old.url}")
            lines.append(f"Final: {response.status_code} -> {response.url}")
        else:
            lines.append("No redirects observed.")

        lines.extend(["", "SECURITY HEADERS", "-" * 54])
        present = 0
        for header, description in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            if value:
                present += 1
                lines.append(f"[PRESENT] {header}: {value}")
            else:
                lines.append(f"[MISSING] {header} — {description}")

        lines.extend(["", "INFORMATION EXPOSURE", "-" * 54])
        for header in ("Server", "X-Powered-By", "X-AspNet-Version"):
            lines.append(f"{header}: {response.headers.get(header, 'Not disclosed')}")

        lines.extend(["", "COOKIE FLAGS", "-" * 54])
        cookies = response.cookies
        if not cookies:
            lines.append("No cookies were set in this response.")
        else:
            for cookie in cookies:
                lines.append(
                    f"{cookie.name}: Secure={bool(cookie.secure)}, "
                    f"HttpOnly={cookie.has_nonstandard_attr('HttpOnly')}, "
                    f"SameSite={cookie.get_nonstandard_attr('SameSite') or 'Not specified'}"
                )

        score = round((present / len(SECURITY_HEADERS)) * 100)
        lines.extend(["", f"Security-header coverage: {score}/100",
                      "This is header coverage only, not an overall security grade.",
                      "Cookie flags reflect cookies visible to this HTTP response."])
    except requests.exceptions.SSLError as exc:
        lines.append(f"TLS/SSL verification error: {exc}")
    except requests.exceptions.Timeout:
        lines.append("Request timed out.")
    except requests.exceptions.RequestException as exc:
        lines.append(f"Request failed: {exc}")
    return "\n".join(lines)
