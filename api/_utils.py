import ipaddress
import json
import re
import socket
from urllib.parse import urlparse, parse_qs


def get_param(handler, name):
    q = parse_qs(urlparse(handler.path).query)
    return q.get(name, [""])[0].strip()


def respond(handler, code, data):
    body = json.dumps(data, default=str).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def clean_host(target):
    t = target.strip()
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
