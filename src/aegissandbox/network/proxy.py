"""Forwarding HTTP/CONNECT Egress Allowlist Proxy for AI Sandboxes."""

import socket
import select
import threading
import fnmatch
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import List, Optional, Callable
import urllib.request
import urllib.error

class EgressProxyHandler(BaseHTTPRequestHandler):
    server: "EgressProxyServer"

    def log_message(self, format, *args):
        # Suppress noisy console logs
        pass

    def _extract_host(self) -> str:
        if self.command == "CONNECT":
            return self.path.split(":")[0]
        else:
            host_header = self.headers.get("Host", "")
            return host_header.split(":")[0]

    def do_CONNECT(self):
        """Handles HTTPS tunneling via HTTP CONNECT method."""
        host = self._extract_host()
        try:
            port = int(self.path.split(":")[1])
        except Exception:
            port = 443

        if not self.server.is_allowed(host):
            self.server.record_audit(host, port, "BLOCKED", "CONNECT")
            self.send_response(403, "Forbidden")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"[Aegis-Sandbox] Egress to host '{host}' is blocked by policy.\n".encode())
            return

        self.server.record_audit(host, port, "ALLOWED", "CONNECT")
        try:
            upstream = socket.create_connection((host, port), timeout=5.0)
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        # Pipe bi-directionally between client socket and upstream
        client_sock = self.connection
        sockets = [client_sock, upstream]
        try:
            while True:
                r, _, _ = select.select(sockets, [], sockets, 10.0)
                if not r:
                    break
                for s in r:
                    other = upstream if s is client_sock else client_sock
                    data = s.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            pass
        finally:
            upstream.close()

    def do_GET(self):
        self._handle_http_forward()

    def do_POST(self):
        self._handle_http_forward()

    def do_PUT(self):
        self._handle_http_forward()

    def do_DELETE(self):
        self._handle_http_forward()

    def do_HEAD(self):
        self._handle_http_forward()

    def _handle_http_forward(self):
        host = self._extract_host()
        port = 80
        if not self.server.is_allowed(host):
            self.server.record_audit(host, port, "BLOCKED", self.command)
            self.send_response(403, "Forbidden")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"[Aegis-Sandbox] Egress to host '{host}' is blocked by policy.\n".encode())
            return

        self.server.record_audit(host, port, "ALLOWED", self.command)
        
        # Read request body if present
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else None

        req_headers = {k: v for k, v in self.headers.items() if k.lower() not in ["proxy-connection"]}
        url = self.path
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{host}{url}"

        try:
            req = urllib.request.Request(url, data=body, headers=req_headers, method=self.command)
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")

class EgressProxyServer(HTTPServer):
    def __init__(
        self,
        port: int = 8080,
        allowed_domains: Optional[List[str]] = None,
        audit_callback: Optional[Callable[[str, int, str, str], None]] = None
    ):
        self.allowed_domains = allowed_domains or []
        self.audit_callback = audit_callback
        self._thread: Optional[threading.Thread] = None
        super().__init__(("127.0.0.1", port), EgressProxyHandler)

    def is_allowed(self, host: str) -> bool:
        if "*" in self.allowed_domains:
            return True
        for pattern in self.allowed_domains:
            if fnmatch.fnmatch(host.lower(), pattern.lower()):
                return True
        return False

    def record_audit(self, host: str, port: int, verdict: str, method: str):
        if self.audit_callback:
            self.audit_callback(host, port, verdict, method)

    def start(self):
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)
