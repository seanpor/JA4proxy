#!/usr/bin/env python3
"""Minimal HTTPS backend for Go proxy integration tests."""
import ssl
import http.server


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress access logs


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/cert.pem", "/key.pem")
server = http.server.HTTPServer(("0.0.0.0", 443), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("TLS backend listening on :443", flush=True)
server.serve_forever()
