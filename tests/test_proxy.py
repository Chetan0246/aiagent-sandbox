import unittest
import time
import urllib.request
import urllib.error
from aegissandbox.network.proxy import EgressProxyServer

class TestEgressProxy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.allowed = ["httpbin.org", "api.openai.com", "localhost", "127.0.0.1"]
        cls.proxy = EgressProxyServer(port=18888, allowed_domains=cls.allowed)
        cls.proxy.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()

    def test_domain_allowlist_matching(self):
        self.assertTrue(self.proxy.is_allowed("api.openai.com"))
        self.assertTrue(self.proxy.is_allowed("httpbin.org"))
        self.assertFalse(self.proxy.is_allowed("evil.attacker.com"))
        self.assertFalse(self.proxy.is_allowed("malicious-exfil.xyz"))

    def test_blocked_domain_returns_403(self):
        proxy_handler = urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:18888",
            "https": "http://127.0.0.1:18888"
        })
        opener = urllib.request.build_opener(proxy_handler)
        
        req = urllib.request.Request("http://evil.attacker.com/steal-data")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            opener.open(req, timeout=2)
            
        self.assertEqual(ctx.exception.code, 403)

if __name__ == "__main__":
    unittest.main()
