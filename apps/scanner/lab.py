"""A tiny local web server used ONLY for safe scanner testing (lab mode).

Routes
  /weak          no security headers, insecure cookies, version-revealing headers
  /hardened      good headers and cookies
  /redirect-ok   302 -> /hardened
  /redirect-evil 302 -> http://169.254.169.254/ (the scanner must refuse to follow)
  /redirect-loop 302 -> itself
  /slow          waits 15 seconds (timeout testing)
  /big           returns ~1 MB (size-limit testing)

It binds to 127.0.0.1 only.
"""
from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"<!doctype html><title>EagleEye lab</title><h1>EagleEye lab target</h1>"


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabServer/1.0.3"  # deliberately reveals a version on /weak
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):  # keep the console quiet
        pass

    def _send(self, status=200, headers=(), body=PAGE):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/weak":
            self._send(headers=[
                ("Content-Type", "text/html"), ("X-Powered-By", "PythonLab"),
                ("Set-Cookie", "sessionid=abc123; Path=/"),
                ("Set-Cookie", "theme=dark; Path=/; SameSite=None"),
            ])
        elif path == "/hardened":
            self._send(headers=[
                ("Content-Type", "text/html"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
                ("Set-Cookie", "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"),
            ])
        elif path == "/redirect-ok":
            self._send(302, [("Location", "/hardened")], b"")
        elif path == "/redirect-evil":
            self._send(302, [("Location", "http://169.254.169.254/latest/meta-data/")], b"")
        elif path == "/redirect-loop":
            self._send(302, [("Location", "/redirect-loop")], b"")
        elif path == "/slow":
            time.sleep(15)
            self._send()
        elif path == "/big":
            self._send(body=b"A" * 1_000_000)
        else:
            self._send(404, body=b"not found")


def make_server(port: int = 8001) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    server.daemon_threads = True
    return server
