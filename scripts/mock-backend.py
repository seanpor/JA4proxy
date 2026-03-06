#!/usr/bin/env python3
"""
Mock backend server for testing JA4 Proxy
Provides various endpoints for testing proxy functionality
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import ssl
import time
from datetime import datetime

class MockBackendHandler(BaseHTTPRequestHandler):
    """Simple mock backend for testing."""
    
    def log_message(self, format, *args):
        """Log with timestamp."""
        print(f"[{datetime.now().isoformat()}] {format % args}")
    
    def _send_response(self, status=200, content_type="text/html", body=""):
        """Send HTTP response."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body.encode())))
        self.send_header("Server", "MockBackend/1.0")
        self.end_headers()
        self.wfile.write(body.encode())
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/" or self.path == "/index.html":
            body = """<!DOCTYPE html>
<html>
<head>
    <title>JA4 Proxy Mock Backend</title>
</head>
<body>
    <h1>Mock Backend Server</h1>
    <p>This is a test backend for JA4 Proxy.</p>
    <p>Timestamp: <span id="ts"></span></p>
    <script>document.getElementById('ts').textContent = new Date().toISOString();</script>
</body>
</html>"""
            self._send_response(200, "text/html", body)
        
        elif self.path == "/api/health":
            body = json.dumps({
                "status": "ok",
                "timestamp": time.time(),
                "service": "mock-backend"
            })
            self._send_response(200, "application/json", body)
        
        elif self.path == "/api/echo":
            body = json.dumps({
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "timestamp": time.time()
            })
            self._send_response(200, "application/json", body)
        
        elif self.path.startswith("/delay/"):
            # Parse delay time from path
            try:
                delay = int(self.path.split("/")[-1])
                time.sleep(min(delay, 10))  # Max 10 seconds
                body = json.dumps({"delayed": delay, "timestamp": time.time()})
                self._send_response(200, "application/json", body)
            except ValueError:
                self._send_response(400, "text/plain", "Invalid delay value")
        
        elif self.path.startswith("/status/"):
            # Return specific status code
            try:
                status = int(self.path.split("/")[-1])
                body = json.dumps({"status": status, "timestamp": time.time()})
                self._send_response(status, "application/json", body)
            except ValueError:
                self._send_response(400, "text/plain", "Invalid status code")
        
        else:
            self._send_response(404, "text/plain", "Not Found")
    
    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ""
        
        response = json.dumps({
            "method": "POST",
            "path": self.path,
            "body": body,
            "timestamp": time.time()
        })
        self._send_response(200, "application/json", response)
    
    def do_PUT(self):
        """Handle PUT requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ""
        
        response = json.dumps({
            "method": "PUT",
            "path": self.path,
            "body": body,
            "timestamp": time.time()
        })
        self._send_response(200, "application/json", response)
    
    def do_DELETE(self):
        """Handle DELETE requests."""
        response = json.dumps({
            "method": "DELETE",
            "path": self.path,
            "timestamp": time.time()
        })
        self._send_response(200, "application/json", response)


def run_server(port=None, tls=None):
    """Run the mock backend server, optionally with TLS."""
    tls_cert = tls or os.environ.get('TLS_CERT')
    tls_key = os.environ.get('TLS_KEY')

    if tls_cert and os.path.exists(tls_cert):
        port = port or int(os.environ.get('PORT', 443))
        server_address = ('', port)
        httpd = HTTPServer(server_address, MockBackendHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_cert, tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"Mock backend server started on HTTPS port {port}")
    else:
        port = port or int(os.environ.get('PORT', 80))
        server_address = ('', port)
        httpd = HTTPServer(server_address, MockBackendHandler)
        print(f"Mock backend server started on HTTP port {port}")

    print(f"Available endpoints:")
    print(f"  GET  / - HTML homepage")
    print(f"  GET  /api/health - Health check")
    print(f"  GET  /api/echo - Echo request details")
    print(f"  GET  /delay/<seconds> - Delayed response")
    print(f"  GET  /status/<code> - Return specific status code")
    print(f"  POST /api/echo - Echo POST request")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.shutdown()


if __name__ == "__main__":
    run_server()
