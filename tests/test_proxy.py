import http.server
import threading
import time
import unittest
import urllib.error
import urllib.request

from aegissandbox.network.proxy import EgressProxyServer


class DummyHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"upstream response ok")

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(content_len) if content_len > 0 else b""
        self.send_response(201)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(b"echo: " + data)

    def log_message(self, format, *args):
        pass


class TestEgressProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start mock upstream server
        cls.upstream_server = http.server.HTTPServer(("127.0.0.1", 18889), DummyHTTPHandler)
        cls.upstream_thread = threading.Thread(target=cls.upstream_server.serve_forever, daemon=True)
        cls.upstream_thread.start()

        cls.allowed = ["httpbin.org", "api.openai.com", "localhost", "127.0.0.1"]
        cls.proxy = EgressProxyServer(port=18888, allowed_domains=cls.allowed)
        cls.proxy.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.upstream_server.shutdown()
        cls.upstream_server.server_close()

    def test_domain_allowlist_matching(self):
        self.assertTrue(self.proxy.is_allowed("api.openai.com"))
        self.assertTrue(self.proxy.is_allowed("httpbin.org"))
        self.assertFalse(self.proxy.is_allowed("evil.attacker.com"))
        self.assertFalse(self.proxy.is_allowed("malicious-exfil.xyz"))

    def test_blocked_domain_returns_403(self):
        proxy_handler = urllib.request.ProxyHandler(
            {"http": "http://127.0.0.1:18888", "https": "http://127.0.0.1:18888"}
        )
        opener = urllib.request.build_opener(proxy_handler)

        req = urllib.request.Request("http://evil.attacker.com/steal-data")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            opener.open(req, timeout=2)

        self.assertEqual(ctx.exception.code, 403)

    def test_allowed_http_get_forwarding(self):
        proxy_handler = urllib.request.ProxyHandler({"http": "http://127.0.0.1:18888"})
        opener = urllib.request.build_opener(proxy_handler)

        req = urllib.request.Request("http://127.0.0.1:18889/test-get")
        with opener.open(req, timeout=2) as resp:
            self.assertEqual(resp.status, 200)
            data = resp.read()
            self.assertIn(b"upstream response ok", data)

    def test_allowed_http_post_forwarding(self):
        proxy_handler = urllib.request.ProxyHandler({"http": "http://127.0.0.1:18888"})
        opener = urllib.request.build_opener(proxy_handler)

        req = urllib.request.Request(
            "http://127.0.0.1:18889/test-post",
            data=b"hello_agent",
            headers={"Content-Type": "text/plain"},
        )
        with opener.open(req, timeout=2) as resp:
            self.assertEqual(resp.status, 201)
            data = resp.read()
            self.assertIn(b"echo: hello_agent", data)


if __name__ == "__main__":
    unittest.main()
