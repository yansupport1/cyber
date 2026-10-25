from http.server import BaseHTTPRequestHandler
import socket
import time
from concurrent.futures import ThreadPoolExecutor

try:
    from _utils import get_param, respond, clean_host, resolve_public
except ImportError:
    from api._utils import get_param, respond, clean_host, resolve_public

COMMON = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    27017: "mongodb",
}
MAX_PORTS = 100


def parse_ports(raw):
    if not raw or raw == "common":
        return sorted(COMMON)
    ports = set()
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    ports = sorted(p for p in ports if 1 <= p <= 65535)
    if not ports:
        raise ValueError("Port tidak valid")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Maksimal {MAX_PORTS} port per scan")
    return ports


def check(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        return port, s.connect_ex((ip, port)) == 0
    except Exception:
        return port, False
    finally:
        s.close()


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            host = clean_host(get_param(self, "target"))
            ip = resolve_public(host)
            ports = parse_ports(get_param(self, "ports"))
            start = time.time()
            with ThreadPoolExecutor(max_workers=50) as ex:
                results = list(ex.map(lambda p: check(ip, p), ports))
            open_ports = [
                {"port": p, "state": "open", "service": COMMON.get(p, "unknown")}
                for p, ok in results if ok
            ]
            respond(self, 200, {
                "tool": "port-scan", "target": host, "ip": ip,
                "scanned": len(ports), "open": open_ports,
                "duration": round(time.time() - start, 2),
            })
        except ValueError as e:
            respond(self, 400, {"error": str(e)})
        except Exception as e:
            respond(self, 500, {"error": f"Server error: {e}"})
