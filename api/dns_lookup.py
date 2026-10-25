from http.server import BaseHTTPRequestHandler
import socket

try:
    from _utils import get_param, respond, clean_host
except ImportError:
    from api._utils import get_param, respond, clean_host


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            host = clean_host(get_param(self, "target"))
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
            respond(self, 200, {
                "tool": "dns-lookup", "host": host,
                "ipv4": ipv4, "ipv6": ipv6, "reverse_dns": reverse,
            })
        except ValueError as e:
            respond(self, 400, {"error": str(e)})
        except Exception as e:
            respond(self, 500, {"error": f"Server error: {e}"})
