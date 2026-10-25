from http.server import BaseHTTPRequestHandler
import requests

try:
    from _utils import get_param, respond, clean_host, resolve_public
except ImportError:
    from api._utils import get_param, respond, clean_host, resolve_public

SECURITY = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            raw = get_param(self, "target")
            host = clean_host(raw)
            resolve_public(host)
            url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
            r = requests.get(
                url, timeout=6, allow_redirects=False,
                headers={"User-Agent": "CyberToolsPanel/1.0"},
            )
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            checks = [
                {"header": h, "present": h.lower() in hdrs,
                 "value": hdrs.get(h.lower(), None)}
                for h in SECURITY
            ]
            score = sum(1 for c in checks if c["present"])
            respond(self, 200, {
                "tool": "http-headers", "url": url, "status": r.status_code,
                "security_score": f"{score}/{len(SECURITY)}",
                "security_checks": checks,
                "all_headers": dict(r.headers),
            })
        except ValueError as e:
            respond(self, 400, {"error": str(e)})
        except requests.RequestException as e:
            respond(self, 502, {"error": f"Request gagal: {type(e).__name__}"})
        except Exception as e:
            respond(self, 500, {"error": f"Server error: {e}"})
