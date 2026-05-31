import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import server


class TaskForgeApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        suffix = f"{os.getpid()}-{threading.get_ident()}"
        server.DB_FILE = server.APP_DATA_DIR / f"taskforge-test-{suffix}.db"
        server.LEGACY_DATA_FILE = server.APP_DATA_DIR / f"items-test-{suffix}.json"
        for path in (server.DB_FILE, server.LEGACY_DATA_FILE):
            path.unlink(missing_ok=True)
        server.init_database()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.TaskForgeHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for path in (server.DB_FILE, server.LEGACY_DATA_FILE):
            try:
                path.unlink(missing_ok=True)
            except PermissionError:
                pass

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def request(self, method, path, body=None, token=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.url(path), data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                payload = response.read()
                return response.status, json.loads(payload.decode("utf-8")) if payload else None
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            return exc.code, json.loads(payload.decode("utf-8")) if payload else None

    def login(self):
        status, body = self.request("POST", "/v1/auth/login", {
            "email": server.DEMO_EMAIL,
            "password": server.DEMO_PASSWORD,
        })
        self.assertEqual(status, 200)
        return body["token"]

    def test_health_is_public(self):
        status, body = self.request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_items_require_auth(self):
        status, body = self.request("GET", "/v1/items")
        self.assertEqual(status, 401)
        self.assertEqual(body["code"], "UNAUTHORIZED")

    def test_login_me_and_crud_flow(self):
        token = self.login()

        status, me = self.request("GET", "/v1/me", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(me["user"]["email"], server.DEMO_EMAIL)

        status, created = self.request("POST", "/v1/items", {
            "name": "Test Laptop",
            "description": "Useful work machine",
            "price": 1200,
            "currency": "USD",
            "status": "active",
            "tags": ["hardware"],
        }, token=token)
        self.assertEqual(status, 201)
        self.assertTrue(created["id"].startswith("item_"))

        status, listed = self.request("GET", "/v1/items?search=laptop&status=active", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(listed["meta"]["totalItems"], 1)

        status, patched = self.request("PATCH", f"/v1/items/{created['id']}", {
            "status": "archived",
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(patched["status"], "archived")

        status, _ = self.request("DELETE", f"/v1/items/{created['id']}", token=token)
        self.assertEqual(status, 204)

    def test_currency_is_required_when_price_is_set(self):
        token = self.login()
        status, body = self.request("POST", "/v1/items", {
            "name": "Bad Item",
            "price": 10,
        }, token=token)
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "INVALID_REQUEST")


if __name__ == "__main__":
    unittest.main()
