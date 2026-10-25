from http.server import BaseHTTPRequestHandler
import whois

try:
    from _utils import get_param, respond, clean_host
except ImportError:
    from api._utils import get_param, respond, clean_host


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            domain = clean_host(get_param(self, "target"))
            w = whois.whois(domain)
            data = {k: v for k, v in dict(w).items() if v not in (None, [], "")}
            if not data:
                raise ValueError("Data whois tidak ditemukan")
            respond(self, 200, {"tool": "whois", "domain": domain, "data": data})
        except ValueError as e:
            respond(self, 400, {"error": str(e)})
        except Exception as e:
            respond(self, 500, {"error": f"Whois gagal: {type(e).__name__}"})
