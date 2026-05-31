from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
from datetime import datetime, UTC
from pathlib import Path


HOST = "127.0.0.1"
PORT = 8000
API_PREFIX = "/v1"
LEGACY_DATA_FILE = Path(__file__).with_name("items.json")
APP_DATA_DIR = Path.home() / "AppData" / "Local" / "TaskForge"
DB_FILE = APP_DATA_DIR / "taskforge.db"
DEV_TOKEN = "dev-token"
DEMO_EMAIL = "demo@taskforge.local"
DEMO_PASSWORD = "demo123"
STATUSES = {"active", "archived", "draft"}
SORT_FIELDS = {"createdAt", "updatedAt", "name", "price"}
ID_PATTERN = re.compile(r"^item_[A-Za-z0-9]+$")
CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
TAG_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def now_iso():
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def db():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return salt, digest.hex()


def verify_password(password, salt, password_hash):
    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, password_hash)


def item_from_row(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "price": row["price"],
        "currency": row["currency"],
        "status": row["status"],
        "tags": json.loads(row["tags"] or "[]"),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def init_database():
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                price REAL,
                currency TEXT,
                status TEXT NOT NULL,
                tags TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)

        user = conn.execute("SELECT id FROM users WHERE email = ?", (DEMO_EMAIL,)).fetchone()
        if user is None:
            salt, password_hash = hash_password(DEMO_PASSWORD)
            conn.execute(
                "INSERT INTO users (email, name, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (DEMO_EMAIL, "Demo User", salt, password_hash, now_iso()),
            )

        import_legacy_items(conn)


def demo_user_id(conn):
    row = conn.execute("SELECT id FROM users WHERE email = ?", (DEMO_EMAIL,)).fetchone()
    return row["id"] if row else None


def import_legacy_items(conn):
    if not LEGACY_DATA_FILE.exists():
        return
    has_items = conn.execute("SELECT 1 FROM items LIMIT 1").fetchone()
    if has_items:
        return
    try:
        legacy_items = json.loads(LEGACY_DATA_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    user_id = demo_user_id(conn)
    for item in legacy_items:
        conn.execute(
            """
            INSERT OR IGNORE INTO items
            (id, user_id, name, description, price, currency, status, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.get("id") or make_item_id(),
                user_id,
                item.get("name") or "Untitled item",
                item.get("description"),
                item.get("price"),
                item.get("currency"),
                item.get("status", "draft"),
                json.dumps(item.get("tags", [])),
                item.get("createdAt") or now_iso(),
                item.get("updatedAt") or now_iso(),
            ),
        )


def make_item_id():
    return f"item_{secrets.token_hex(6)}"


def error_payload(message, code, details=None):
    payload = {"message": message, "code": code}
    if details is not None:
        payload["details"] = details
    return payload


def validate_item_payload(payload, partial=False):
    if not isinstance(payload, dict):
        return "Request body must be a JSON object", {"field": "body"}
    if partial and not payload:
        return "Patch body must include at least one field", {"field": "body"}

    allowed = {"name", "description", "price", "currency", "status", "tags"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        return "Request contains unsupported fields", {"fields": unknown}
    if not partial and "name" not in payload:
        return "Name is required", {"field": "name"}

    if "name" in payload:
        name = payload["name"]
        if not isinstance(name, str) or not 1 <= len(name) <= 200:
            return "Name must be a string between 1 and 200 characters", {"field": "name"}
    if "description" in payload:
        value = payload["description"]
        if value is not None and (not isinstance(value, str) or len(value) > 2000):
            return "Description must be null or a string up to 2000 characters", {"field": "description"}
    if "price" in payload:
        price = payload["price"]
        if price is not None and (not isinstance(price, (int, float)) or isinstance(price, bool) or price < 0):
            return "Price must be null or a number greater than or equal to 0", {"field": "price"}
    if "currency" in payload:
        currency = payload["currency"]
        if currency is not None and (not isinstance(currency, str) or not CURRENCY_PATTERN.match(currency)):
            return "Currency must be null or a 3-letter uppercase ISO code", {"field": "currency"}
    if payload.get("price") is not None and payload.get("currency") is None:
        return "Currency is required when price is set", {"field": "currency"}
    if "status" in payload and payload["status"] not in STATUSES:
        return "Status must be active, archived, or draft", {"field": "status"}
    if "tags" in payload:
        tags = payload["tags"]
        if not isinstance(tags, list) or len(tags) > 10:
            return "Tags must be an array with at most 10 values", {"field": "tags"}
        for tag in tags:
            if not isinstance(tag, str) or not 1 <= len(tag) <= 50 or not TAG_PATTERN.match(tag):
                return "Each tag must be 1-50 characters using letters, numbers, underscores, or hyphens", {"field": "tags"}
    return None, None


class TaskForgeHandler(BaseHTTPRequestHandler):
    server_version = "TaskForgeAPI/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, status, payload=None, headers=None):
        self.send_response(status)
        self.send_header("X-Request-ID", f"req_{secrets.token_hex(8)}")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        if headers:
            for key, value in headers.items():
                self.send_header(key, str(value))
        if payload is None:
            self.end_headers()
            return
        body = json.dumps(payload).encode("utf-8")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status, message, code, details=None, headers=None):
        self.send_json(status, error_payload(message, code, details), headers=headers)

    def send_html(self, body):
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("X-Request-ID", f"req_{secrets.token_hex(8)}")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return None, "Request body is required"
        raw_body = self.rfile.read(length)
        try:
            return json.loads(raw_body), None
        except json.JSONDecodeError:
            return None, "Request body must be valid JSON"

    def current_user_id(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth.removeprefix("Bearer ").strip()
        with db() as conn:
            if token == DEV_TOKEN:
                return demo_user_id(conn)
            row = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
            return row["user_id"] if row else None

    def current_user(self, user_id):
        with db() as conn:
            row = conn.execute("SELECT id, email, name FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def require_auth(self):
        user_id = self.current_user_id()
        if user_id:
            return user_id
        self.send_error_json(401, "Authentication token is missing or invalid", "UNAUTHORIZED")
        return None

    def parsed_path(self):
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def item_id_from_path(self, path):
        prefix = f"{API_PREFIX}/items/"
        if not path.startswith(prefix):
            return None
        item_id = path[len(prefix):]
        if "/" in item_id or not ID_PATTERN.match(item_id):
            return None
        return item_id

    def do_OPTIONS(self):
        self.send_json(204)

    def do_GET(self):
        path, query = self.parsed_path()
        if path == "/" or path == API_PREFIX:
            self.send_home()
            return
        if path in {"/app", "/test"}:
            self.send_app_page()
            return
        if path == f"{API_PREFIX}/health":
            self.send_json(200, {"status": "ok", "service": "TaskForge API"})
            return

        user_id = self.require_auth()
        if not user_id:
            return
        if path == f"{API_PREFIX}/me":
            self.send_json(200, {"user": self.current_user(user_id)})
            return
        if path == f"{API_PREFIX}/items":
            self.list_items(query, user_id)
            return
        item_id = self.item_id_from_path(path)
        if item_id:
            self.get_item(item_id, user_id)
            return
        self.send_error_json(404, "Resource not found", "NOT_FOUND")

    def do_POST(self):
        path, _ = self.parsed_path()
        if path == f"{API_PREFIX}/auth/login":
            self.login()
            return

        user_id = self.require_auth()
        if not user_id:
            return
        if path != f"{API_PREFIX}/items":
            self.send_error_json(404, "Resource not found", "NOT_FOUND")
            return

        payload, body_error = self.read_json_body()
        if body_error:
            self.send_error_json(400, body_error, "INVALID_REQUEST")
            return
        message, details = validate_item_payload(payload)
        if message:
            self.send_error_json(400, message, "INVALID_REQUEST", details)
            return

        timestamp = now_iso()
        item = {
            "id": make_item_id(),
            "name": payload["name"],
            "description": payload.get("description"),
            "price": payload.get("price"),
            "currency": payload.get("currency"),
            "status": payload.get("status", "draft"),
            "tags": payload.get("tags", []),
            "createdAt": timestamp,
            "updatedAt": timestamp,
        }
        with db() as conn:
            conn.execute(
                """
                INSERT INTO items
                (id, user_id, name, description, price, currency, status, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["id"], user_id, item["name"], item["description"], item["price"], item["currency"],
                    item["status"], json.dumps(item["tags"]), item["createdAt"], item["updatedAt"],
                ),
            )
        self.send_json(201, item)

    def do_PUT(self):
        user_id = self.require_auth()
        if not user_id:
            return
        path, _ = self.parsed_path()
        item_id = self.item_id_from_path(path)
        if not item_id:
            self.send_error_json(404, "Resource not found", "NOT_FOUND")
            return
        payload, body_error = self.read_json_body()
        if body_error:
            self.send_error_json(400, body_error, "INVALID_REQUEST")
            return
        message, details = validate_item_payload(payload)
        if message:
            self.send_error_json(400, message, "INVALID_REQUEST", details)
            return

        with db() as conn:
            existing = conn.execute(
                "SELECT * FROM items WHERE id = ? AND user_id = ?", (item_id, user_id)
            ).fetchone()
            if existing is None:
                self.send_error_json(404, "Item not found", "NOT_FOUND")
                return
            updated_at = now_iso()
            conn.execute(
                """
                UPDATE items
                SET name = ?, description = ?, price = ?, currency = ?, status = ?, tags = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    payload["name"], payload.get("description"), payload.get("price"), payload.get("currency"),
                    payload.get("status", "draft"), json.dumps(payload.get("tags", [])), updated_at, item_id, user_id,
                ),
            )
            row = conn.execute("SELECT * FROM items WHERE id = ? AND user_id = ?", (item_id, user_id)).fetchone()
        self.send_json(200, item_from_row(row))

    def do_PATCH(self):
        user_id = self.require_auth()
        if not user_id:
            return
        path, _ = self.parsed_path()
        item_id = self.item_id_from_path(path)
        if not item_id:
            self.send_error_json(404, "Resource not found", "NOT_FOUND")
            return
        payload, body_error = self.read_json_body()
        if body_error:
            self.send_error_json(400, body_error, "INVALID_REQUEST")
            return
        message, details = validate_item_payload(payload, partial=True)
        if message:
            self.send_error_json(400, message, "INVALID_REQUEST", details)
            return

        with db() as conn:
            row = conn.execute("SELECT * FROM items WHERE id = ? AND user_id = ?", (item_id, user_id)).fetchone()
            if row is None:
                self.send_error_json(404, "Item not found", "NOT_FOUND")
                return
            item = item_from_row(row)
            updated = {**item, **payload, "updatedAt": now_iso()}
            if updated.get("price") is not None and updated.get("currency") is None:
                self.send_error_json(400, "Currency is required when price is set", "INVALID_REQUEST", {"field": "currency"})
                return
            conn.execute(
                """
                UPDATE items
                SET name = ?, description = ?, price = ?, currency = ?, status = ?, tags = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    updated["name"], updated["description"], updated["price"], updated["currency"],
                    updated["status"], json.dumps(updated["tags"]), updated["updatedAt"], item_id, user_id,
                ),
            )
        self.send_json(200, updated)

    def do_DELETE(self):
        user_id = self.require_auth()
        if not user_id:
            return
        path, _ = self.parsed_path()
        item_id = self.item_id_from_path(path)
        if not item_id:
            self.send_error_json(404, "Resource not found", "NOT_FOUND")
            return
        with db() as conn:
            result = conn.execute("DELETE FROM items WHERE id = ? AND user_id = ?", (item_id, user_id))
            if result.rowcount == 0:
                self.send_error_json(404, "Item not found", "NOT_FOUND")
                return
        self.send_json(204)

    def login(self):
        payload, body_error = self.read_json_body()
        if body_error:
            self.send_error_json(400, body_error, "INVALID_REQUEST")
            return
        email = str(payload.get("email", "")).strip().lower()
        password = str(payload.get("password", ""))
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user is None or not verify_password(password, user["salt"], user["password_hash"]):
                self.send_error_json(401, "Email or password is incorrect", "UNAUTHORIZED")
                return
            token = secrets.token_urlsafe(32)
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                (token, user["id"], now_iso()),
            )
        self.send_json(200, {
            "token": token,
            "tokenType": "Bearer",
            "user": {"id": user["id"], "email": user["email"], "name": user["name"]},
        })

    def list_items(self, query, user_id):
        try:
            page = int(query.get("page", ["1"])[0])
            page_size = int(query.get("pageSize", ["20"])[0])
        except ValueError:
            self.send_error_json(400, "Pagination values must be integers", "INVALID_REQUEST")
            return
        if page < 1 or page_size < 1 or page_size > 100:
            self.send_error_json(400, "Pagination values are out of range", "INVALID_REQUEST")
            return

        status = query.get("status", [None])[0]
        search = query.get("search", [""])[0].lower()
        sort_by = query.get("sortBy", ["createdAt"])[0]
        sort_order = query.get("sortOrder", ["desc"])[0]
        if status is not None and status not in STATUSES:
            self.send_error_json(400, "Status must be active, archived, or draft", "INVALID_REQUEST", {"field": "status"})
            return
        if sort_by not in SORT_FIELDS or sort_order not in {"asc", "desc"}:
            self.send_error_json(400, "Invalid sort field or order", "INVALID_REQUEST")
            return

        with db() as conn:
            rows = conn.execute("SELECT * FROM items WHERE user_id = ?", (user_id,)).fetchall()
        items = [item_from_row(row) for row in rows]
        if search:
            items = [
                item for item in items
                if search in item["name"].lower() or search in (item.get("description") or "").lower()
            ]
        if status:
            items = [item for item in items if item["status"] == status]
        items.sort(key=lambda item: (item.get(sort_by) is None, item.get(sort_by)), reverse=sort_order == "desc")

        total_items = len(items)
        total_pages = math.ceil(total_items / page_size) if total_items else 0
        start = (page - 1) * page_size
        self.send_json(200, {
            "data": items[start:start + page_size],
            "meta": {"page": page, "pageSize": page_size, "totalItems": total_items, "totalPages": total_pages},
        })

    def get_item(self, item_id, user_id):
        with db() as conn:
            row = conn.execute("SELECT * FROM items WHERE id = ? AND user_id = ?", (item_id, user_id)).fetchone()
        if row is None:
            self.send_error_json(404, "Item not found", "NOT_FOUND")
            return
        self.send_json(200, item_from_row(row))

    def send_home(self):
        self.send_html("""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>TaskForge API</title>
    <style>
      body { font-family: Arial, sans-serif; max-width: 760px; margin: 48px auto; padding: 0 20px; line-height: 1.5; color: #18202a; }
      code, pre { background: #f3f5f7; border-radius: 6px; }
      code { padding: 2px 5px; }
      pre { padding: 14px; overflow-x: auto; }
      a { color: #0a66c2; }
    </style>
  </head>
  <body>
    <h1>TaskForge API</h1>
    <p>The backend is running with SQLite storage and login-based access.</p>
    <p>Customer app: <a href="/app">/app</a></p>
    <p>Health check: <a href="/v1/health">/v1/health</a></p>
    <p>Demo login:</p>
    <pre>Email: demo@taskforge.local
Password: demo123</pre>
    <p>API routes:</p>
    <pre>POST   /v1/auth/login
GET    /v1/items
POST   /v1/items
GET    /v1/items/{id}
PUT    /v1/items/{id}
PATCH  /v1/items/{id}
DELETE /v1/items/{id}</pre>
  </body>
</html>""")

    def send_app_page(self):
        self.send_html("""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>TaskForge</title>
    <style>
      :root { --bg:#f6f7fb; --panel:#fff; --text:#142033; --muted:#65758b; --line:#d9e1ec; --blue:#155eef; --blue2:#0d46b7; --red:#c62828; --green:#137a4d; }
      * { box-sizing: border-box; }
      body { margin:0; font-family: Arial, sans-serif; background:var(--bg); color:var(--text); }
      header { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:20px clamp(16px,4vw,42px); background:var(--panel); border-bottom:1px solid var(--line); }
      h1 { margin:0; font-size:28px; line-height:1.1; }
      h2 { margin:0 0 14px; font-size:18px; }
      p { margin:4px 0 0; color:var(--muted); }
      main { display:grid; grid-template-columns: minmax(280px, 420px) 1fr; gap:20px; padding:24px clamp(16px,4vw,42px); }
      section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; }
      label { display:grid; gap:6px; margin-bottom:12px; font-size:13px; font-weight:700; color:#334155; }
      input, select, textarea { width:100%; border:1px solid var(--line); border-radius:6px; padding:10px 11px; font:inherit; background:#fff; color:var(--text); }
      textarea { min-height:76px; resize:vertical; }
      button { border:0; border-radius:6px; padding:10px 13px; background:var(--blue); color:#fff; font-weight:700; cursor:pointer; }
      button:hover { background:var(--blue2); }
      button.secondary { background:#e7edf8; color:#17345d; }
      button.secondary:hover { background:#dbe5f6; }
      button.danger { background:var(--red); }
      .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
      .actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:14px; }
      .items { display:grid; gap:10px; margin-top:14px; }
      .item { width:100%; text-align:left; border:1px solid var(--line); border-radius:8px; padding:12px; background:#fbfcff; color:var(--text); }
      .item strong { display:block; margin-bottom:4px; }
      .item small { color:var(--muted); overflow-wrap:anywhere; }
      .status { margin-top:12px; min-height:20px; color:var(--green); font-weight:700; }
      .hidden { display:none; }
      pre { min-height:170px; max-height:380px; overflow:auto; margin:12px 0 0; padding:14px; border-radius:8px; background:#101827; color:#dbeafe; font-size:13px; line-height:1.45; white-space:pre-wrap; overflow-wrap:anywhere; }
      .login { max-width:420px; margin:64px auto; }
      @media (max-width: 840px) { header { align-items:flex-start; flex-direction:column; } main { grid-template-columns:1fr; } .row { grid-template-columns:1fr; } }
    </style>
  </head>
  <body>
    <div id="loginView" class="login">
      <section>
        <h1>TaskForge</h1>
        <p>Sign in to manage your items.</p>
        <label>Email <input id="email" value="demo@taskforge.local" /></label>
        <label>Password <input id="password" type="password" value="demo123" /></label>
        <div class="actions"><button id="loginBtn" type="button">Sign In</button></div>
        <div id="loginStatus" class="status" aria-live="polite"></div>
      </section>
    </div>

    <div id="appView" class="hidden">
      <header>
        <div>
          <h1>TaskForge</h1>
          <p id="userLine">Item manager</p>
        </div>
        <div class="actions">
          <button id="refreshBtn" type="button">Refresh</button>
          <button id="logoutBtn" class="secondary" type="button">Sign Out</button>
        </div>
      </header>
      <main>
        <section>
          <h2>Item Details</h2>
          <label>Name <input id="name" value="New Laptop" maxlength="200" /></label>
          <label>Description <textarea id="description">Top-spec developer laptop</textarea></label>
          <div class="row">
            <label>Price <input id="price" type="number" min="0" step="0.01" value="2500.50" /></label>
            <label>Currency <input id="currency" value="USD" maxlength="3" /></label>
          </div>
          <div class="row">
            <label>Status
              <select id="status">
                <option value="active">active</option>
                <option value="archived">archived</option>
                <option value="draft">draft</option>
              </select>
            </label>
            <label>Tags <input id="tags" value="hardware,electronics" /></label>
          </div>
          <label>Selected Item ID <input id="selectedId" placeholder="Create or select an item" /></label>
          <div class="actions">
            <button id="createBtn" type="button">Create</button>
            <button id="updateBtn" class="secondary" type="button">Update</button>
            <button id="patchBtn" class="secondary" type="button">Patch Status</button>
            <button id="deleteBtn" class="danger" type="button">Delete</button>
          </div>
          <div id="statusText" class="status" aria-live="polite"></div>
        </section>
        <section>
          <h2>Items</h2>
          <div class="row">
            <label>Search <input id="search" placeholder="Name or description" /></label>
            <label>Status
              <select id="filterStatus">
                <option value="">all</option>
                <option value="active">active</option>
                <option value="archived">archived</option>
                <option value="draft">draft</option>
              </select>
            </label>
          </div>
          <div id="items" class="items"></div>
          <h2 style="margin-top:22px;">API Response</h2>
          <pre id="output">{}</pre>
        </section>
      </main>
    </div>

    <script>
      let token = localStorage.getItem("taskforgeToken") || "";
      const output = document.getElementById("output");
      const statusText = document.getElementById("statusText");
      const loginStatus = document.getElementById("loginStatus");
      const itemsEl = document.getElementById("items");
      const selectedId = document.getElementById("selectedId");

      function show(data, label) {
        if (output) output.textContent = JSON.stringify(data, null, 2);
        statusText.textContent = label || "";
      }

      function setMode(loggedIn, user) {
        document.getElementById("loginView").classList.toggle("hidden", loggedIn);
        document.getElementById("appView").classList.toggle("hidden", !loggedIn);
        if (user) document.getElementById("userLine").textContent = `${user.name} - ${user.email}`;
      }

      function payload() {
        const priceValue = document.getElementById("price").value;
        return {
          name: document.getElementById("name").value.trim(),
          description: document.getElementById("description").value.trim() || null,
          price: priceValue === "" ? null : Number(priceValue),
          currency: document.getElementById("currency").value.trim().toUpperCase() || null,
          status: document.getElementById("status").value,
          tags: document.getElementById("tags").value.split(",").map((tag) => tag.trim()).filter(Boolean)
        };
      }

      async function request(path, options = {}) {
        const response = await fetch(path, {
          ...options,
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(options.headers || {}) }
        });
        if (response.status === 204) return { status: 204, body: null };
        return { status: response.status, body: await response.json() };
      }

      function fillForm(item) {
        document.getElementById("name").value = item.name || "";
        document.getElementById("description").value = item.description || "";
        document.getElementById("price").value = item.price ?? "";
        document.getElementById("currency").value = item.currency || "";
        document.getElementById("status").value = item.status || "draft";
        document.getElementById("tags").value = (item.tags || []).join(",");
        selectedId.value = item.id || "";
      }

      async function listItems() {
        const params = new URLSearchParams();
        const search = document.getElementById("search").value.trim();
        const status = document.getElementById("filterStatus").value;
        if (search) params.set("search", search);
        if (status) params.set("status", status);
        const url = params.toString() ? `/v1/items?${params}` : "/v1/items";
        const result = await request(url);
        if (result.status === 401) {
          localStorage.removeItem("taskforgeToken");
          token = "";
          setMode(false);
          loginStatus.textContent = "Please sign in again.";
          return;
        }
        show(result.body, `List returned ${result.body?.meta?.totalItems ?? 0} item(s).`);
        itemsEl.innerHTML = "";
        for (const item of result.body.data || []) {
          const row = document.createElement("button");
          row.className = "item";
          row.type = "button";
          row.innerHTML = `<strong>${item.name}</strong><small>${item.id} - ${item.status}</small>`;
          row.addEventListener("click", () => fillForm(item));
          itemsEl.appendChild(row);
        }
      }

      document.getElementById("loginBtn").addEventListener("click", async () => {
        const response = await fetch("/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: document.getElementById("email").value,
            password: document.getElementById("password").value
          })
        });
        const body = await response.json();
        if (!response.ok) {
          loginStatus.textContent = body.message || "Login failed.";
          return;
        }
        token = body.token;
        localStorage.setItem("taskforgeToken", token);
        setMode(true, body.user);
        await listItems();
      });

      document.getElementById("logoutBtn").addEventListener("click", () => {
        localStorage.removeItem("taskforgeToken");
        token = "";
        setMode(false);
      });

      document.getElementById("refreshBtn").addEventListener("click", listItems);
      document.getElementById("search").addEventListener("input", listItems);
      document.getElementById("filterStatus").addEventListener("change", listItems);
      document.getElementById("createBtn").addEventListener("click", async () => {
        const result = await request("/v1/items", { method: "POST", body: JSON.stringify(payload()) });
        if (result.body?.id) selectedId.value = result.body.id;
        show(result.body, `Create returned HTTP ${result.status}.`);
        await listItems();
      });
      document.getElementById("updateBtn").addEventListener("click", async () => {
        if (!selectedId.value.trim()) return show({ error: "Select an item first." }, "No item selected.");
        const result = await request(`/v1/items/${selectedId.value.trim()}`, { method: "PUT", body: JSON.stringify(payload()) });
        show(result.body, `Update returned HTTP ${result.status}.`);
        await listItems();
      });
      document.getElementById("patchBtn").addEventListener("click", async () => {
        if (!selectedId.value.trim()) return show({ error: "Select an item first." }, "No item selected.");
        const result = await request(`/v1/items/${selectedId.value.trim()}`, {
          method: "PATCH",
          body: JSON.stringify({ status: document.getElementById("status").value })
        });
        show(result.body, `Patch returned HTTP ${result.status}.`);
        await listItems();
      });
      document.getElementById("deleteBtn").addEventListener("click", async () => {
        if (!selectedId.value.trim()) return show({ error: "Select an item first." }, "No item selected.");
        const result = await request(`/v1/items/${selectedId.value.trim()}`, { method: "DELETE" });
        selectedId.value = "";
        show(result, `Delete returned HTTP ${result.status}.`);
        await listItems();
      });

      if (token) {
        setMode(true);
        request("/v1/me").then((result) => {
          if (result.status === 200) setMode(true, result.body.user);
          return listItems();
        });
      } else {
        setMode(false);
      }
    </script>
  </body>
</html>""")


def main():
    init_database()
    server = ThreadingHTTPServer((HOST, PORT), TaskForgeHandler)
    print(f"TaskForge API running at http://{HOST}:{PORT}")
    print(f"Demo login: {DEMO_EMAIL} / {DEMO_PASSWORD}")
    server.serve_forever()


if __name__ == "__main__":
    main()
