import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC",
    139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}

def parse_ports(port_spec):
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            pieces = part.split("-", 1)
            if len(pieces) != 2:
                raise ValueError("Invalid port range.")
            start, end = map(int, pieces)
            if start > end:
                raise ValueError("Port range start must be <= end.")
            if start < 1 or end > 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.add(port)
    if not ports:
        raise ValueError("No valid ports supplied.")
    if len(ports) > 5000:
        raise ValueError("For safety and performance, scan at most 5000 ports at a time.")
    return sorted(ports)

def _check_port(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            start = datetime.now()
            result = sock.connect_ex((host, port))
            elapsed = (datetime.now() - start).total_seconds() * 1000
            if result == 0:
                return port, True, elapsed
    except (socket.gaierror, OSError):
        return port, False, 0
    return port, False, 0

def scan_ports(host, port_spec="1-1024", timeout=0.5):
    try:
        ip = socket.gethostbyname(host)
        ports = parse_ports(port_spec)
    except (socket.gaierror, ValueError) as exc:
        return f"Could not start scan: {exc}"

    lines = [
        "NETSENTRY — TCP PORT SCAN",
        "=" * 54,
        f"Target: {host} ({ip})",
        f"Ports checked: {len(ports)}",
        f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(_check_port, ip, p, timeout) for p in ports]
        for future in as_completed(futures):
            port, is_open, elapsed = future.result()
            if is_open:
                open_ports.append((port, elapsed))

    open_ports.sort()
    lines.append("OPEN PORTS")
    lines.append("-" * 54)
    if not open_ports:
        lines.append("No open TCP ports found in the selected range.")
    else:
        lines.append(f"{'PORT':<10}{'SERVICE':<18}{'RESPONSE':>12}")
        for port, elapsed in open_ports:
            service = COMMON_SERVICES.get(port, "Unknown")
            lines.append(f"{port:<10}{service:<18}{elapsed:>9.1f} ms")

    # Simple informational score based on count and commonly exposed services.
    high_attention = {21, 23, 445, 3389, 5900, 6379}
    score = max(0, 100 - min(60, len(open_ports) * 8)
                - min(40, sum(7 for p, _ in open_ports if p in high_attention)))
    lines.extend(["", f"Exposure indicator: {score}/100 (higher means fewer detected open-port indicators)",
                  "This is a basic heuristic, not a vulnerability assessment.",
                  "Finished: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    return "\n".join(lines)
