import ipaddress
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
import whois
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)
PUBLIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")


# ---------- helpers ----------
def clean_host(target):
    t = (target or "").strip()
    if "://" not in t:
        t = "//" + t
    host = urlparse(t).hostname
    if not host or len(host) > 253 or not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        raise ValueError("Target tidak valid")
    return host


def resolve_public(host):
    """Resolve host & blokir IP privat/internal (anti-SSRF)."""
    try:
        ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except socket.gaierror:
        raise ValueError("Host tidak bisa di-resolve")
    if not ipaddress.ip_address(ip).is_global:
        raise ValueError("IP privat/internal diblokir")
    return ip


@app.errorhandler(ValueError)
def on_value_error(e):
    return jsonify(error=str(e)), 400


@app.errorhandler(Exception)
def on_error(e):
    if hasattr(e, "code") and isinstance(e.code, int):  # HTTPException (404 dll)
        return jsonify(error=getattr(e, "description", "Error")), e.code
    return jsonify(error=f"Server error: {type(e).__name__}"), 500


# ---------- port scanner ----------
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


def check_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        return port, s.connect_ex((ip, port)) == 0
    except Exception:
        return port, False
    finally:
        s.close()


@app.route("/api/scan")
def scan():
    host = clean_host(request.args.get("target"))
    ip = resolve_public(host)
    try:
        ports = parse_ports(request.args.get("ports", "").strip())
    except ValueError:
        raise ValueError("Format port tidak valid")
    start = time.time()
    with ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(lambda p: check_port(ip, p), ports))
    open_ports = [
        {"port": p, "state": "open", "service": COMMON.get(p, "unknown")}
        for p, ok in results if ok
    ]
    return jsonify(tool="port-scan", target=host, ip=ip, scanned=len(ports),
                   open=open_ports, duration=round(time.time() - start, 2))


# ---------- http headers ----------
SECURITY = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]


@app.route("/api/headers")
def headers():
    raw = (request.args.get("target") or "").strip()
    host = clean_host(raw)
    resolve_public(host)
    url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
    try:
        r = requests.get(url, timeout=6, allow_redirects=False,
                         headers={"User-Agent": "CyberToolsPanel/1.0"})
    except requests.RequestException as e:
        return jsonify(error=f"Request gagal: {type(e).__name__}"), 502
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    checks = [{"header": h, "present": h.lower() in hdrs,
               "value": hdrs.get(h.lower())} for h in SECURITY]
    score = sum(1 for c in checks if c["present"])
    return jsonify(tool="http-headers", url=url, status=r.status_code,
                   security_score=f"{score}/{len(SECURITY)}",
                   security_checks=checks, all_headers=dict(r.headers))


# ---------- whois ----------
@app.route("/api/whois_lookup")
def whois_lookup():
    domain = clean_host(request.args.get("target"))
    w = whois.whois(domain)
    data = {k: (v if isinstance(v, (str, int, float, list, type(None))) else str(v))
            for k, v in dict(w).items() if v not in (None, [], "")}
    if not data:
        raise ValueError("Data whois tidak ditemukan")
    for k, v in data.items():
        if isinstance(v, list):
            data[k] = [x if isinstance(x, (str, int, float)) else str(x) for x in v]
    return jsonify(tool="whois", domain=domain, data=data)


# ---------- dns ----------
@app.route("/api/dns_lookup")
def dns_lookup():
    host = clean_host(request.args.get("target"))
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("Domain tidak ditemukan")
    ipv4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    ipv6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    reverse = None
    if ipv4:
        try:
            reverse = socket.gethostbyaddr(ipv4[0])[0]
        except Exception:
            pass
    return jsonify(tool="dns-lookup", host=host, ipv4=ipv4, ipv6=ipv6,
                   reverse_dns=reverse)


# ---------- static (fallback; Vercel biasanya sudah serve /public) ----------
@app.route("/")
def index():
    return send_from_directory(PUBLIC, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(PUBLIC, filename)


if __name__ == "__main__":
    app.run(debug=True)
