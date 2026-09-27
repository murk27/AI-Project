"""Minimal stdlib-only HTTP server that echoes back a fixed 200 response.
Used only as a fake 'destination' (e.g. a shadow-AI chat endpoint) for
integration-testing the proxy addon locally, without any third-party deps.
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = b'{"reply": "this request reached the real destination"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
