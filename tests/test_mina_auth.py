"""
Test suite for MINA auth + web UI + credential generator (low-spec).

Covers:
  1. Auth store     — PBKDF2 hashing, validation, atomic chmod-600 files
  2. Sessions       — in-memory TTL, cap, one-time fields
  3. Attempt limiter— login brute-force guard
  4. Credentials    — generation, masking, storage format
  5. Web UI flow    — setup → login → dashboard → generate → reveal-once
  6. Security       — CSRF, locked /command when unconfigured, no leaks

Run:
    cd the repository root
    python3 -m pytest tests/test_mina_auth.py -v
"""
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# Fast PBKDF2 for tests (still exercises the full code path)
os.environ.setdefault("MINA_AUTH_ITERATIONS", "1000")

import mina_auth  # noqa: E402
import mina_webui  # noqa: E402


# ════════════════════════════════════════════════════════════════
# 1. AUTH STORE — hashing & validation
# ════════════════════════════════════════════════════════════════

class TestPasswordHashing:
    def test_hash_and_verify_roundtrip(self):
        rec = mina_auth.hash_password("correct horse battery")
        assert mina_auth.verify_password("correct horse battery", rec) is True

    def test_wrong_password_fails(self):
        rec = mina_auth.hash_password("right")
        assert mina_auth.verify_password("wrong", rec) is False

    def test_salt_is_random(self):
        r1 = mina_auth.hash_password("same")
        r2 = mina_auth.hash_password("same")
        assert r1["salt"] != r2["salt"]
        assert r1["hash"] != r2["hash"]

    def test_record_has_expected_fields(self):
        rec = mina_auth.hash_password("x" * 10)
        assert rec["algo"] == "pbkdf2_sha256"
        assert rec["iterations"] == mina_auth.default_iterations()
        assert len(rec["salt"]) == 32

    def test_verify_never_raises_on_garbage(self):
        assert mina_auth.verify_password("x", {}) is False
        assert mina_auth.verify_password("x", {"salt": "zz"}) is False


class TestValidation:
    def test_valid_username(self):
        assert mina_auth.validate_username("admin") is None
        assert mina_auth.validate_username("hermes_01.x") is None

    def test_short_username_rejected(self):
        assert mina_auth.validate_username("ab") is not None

    def test_bad_chars_username_rejected(self):
        assert mina_auth.validate_username("admin; rm -rf") is not None
        assert mina_auth.validate_username("admin space") is not None

    def test_short_password_rejected(self):
        assert mina_auth.validate_password("short") is not None

    def test_valid_password(self):
        assert mina_auth.validate_password("longenough123") is None


class TestUserStore:
    def test_set_and_check_password(self, tmp_path):
        path = tmp_path / "auth.json"
        mina_auth.set_password("admin", "secret123", path=path)
        assert mina_auth.check_password("admin", "secret123", path=path) is True
        assert mina_auth.check_password("admin", "wrong", path=path) is False
        assert mina_auth.check_password("other", "secret123", path=path) is False

    def test_auth_file_is_chmod_600(self, tmp_path):
        path = tmp_path / "auth.json"
        mina_auth.set_password("admin", "secret123", path=path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_auth_file_contains_no_plaintext(self, tmp_path):
        path = tmp_path / "auth.json"
        mina_auth.set_password("admin", "supersecret123", path=path)
        raw = path.read_text()
        assert "supersecret123" not in raw
        data = json.loads(raw)
        assert data["password"]["algo"] == "pbkdf2_sha256"

    def test_is_configured(self, tmp_path):
        path = tmp_path / "auth.json"
        assert mina_auth.is_configured(path) is False
        mina_auth.set_password("admin", "secret123", path=path)
        assert mina_auth.is_configured(path) is True


# ════════════════════════════════════════════════════════════════
# 2. SESSIONS
# ════════════════════════════════════════════════════════════════

class TestSessions:
    def test_create_and_get(self):
        store = mina_auth.SessionStore()
        s = store.create("admin")
        got = store.get(s["token"])
        assert got is not None
        assert got["username"] == "admin"
        assert got["csrf"]

    def test_unknown_token(self):
        assert mina_auth.SessionStore().get("nope") is None

    def test_expiry(self):
        store = mina_auth.SessionStore(ttl_seconds=1)
        s = store.create("admin")
        time.sleep(1.2)
        assert store.get(s["token"]) is None

    def test_destroy(self):
        store = mina_auth.SessionStore()
        s = store.create("admin")
        store.destroy(s["token"])
        assert store.get(s["token"]) is None

    def test_cap_evicts_oldest(self):
        store = mina_auth.SessionStore(max_sessions=2)
        s1 = store.create("a")
        store.create("b")
        store.create("c")  # evicts a
        assert store.get(s1["token"]) is None
        assert store.count() == 2

    def test_one_time_field(self):
        store = mina_auth.SessionStore()
        s = store.create("admin")
        store.set_field(s["token"], "pending_reveal", {"k": "v"})
        first = store.pop_field(s["token"], "pending_reveal")
        second = store.pop_field(s["token"], "pending_reveal")
        assert first == {"k": "v"}
        assert second is None  # consumed — this is the one-time contract


class TestAttemptLimiter:
    def test_allows_until_limit(self):
        lim = mina_auth.AttemptLimiter(max_attempts=3, window_seconds=60)
        for _ in range(3):
            assert lim.allow("ip:1") is True
            lim.record_failure("ip:1")
        assert lim.allow("ip:1") is False

    def test_window_expiry(self):
        lim = mina_auth.AttemptLimiter(max_attempts=1, window_seconds=1)
        lim.record_failure("ip:1")
        assert lim.allow("ip:1") is False
        time.sleep(1.2)
        assert lim.allow("ip:1") is True

    def test_reset(self):
        lim = mina_auth.AttemptLimiter(max_attempts=1)
        lim.record_failure("ip:1")
        lim.reset("ip:1")
        assert lim.allow("ip:1") is True


# ════════════════════════════════════════════════════════════════
# 3. CREDENTIAL GENERATOR
# ════════════════════════════════════════════════════════════════

class TestCredentials:
    def test_generate_format(self):
        assert mina_auth.generate_api_key().startswith("mina_sk_")
        assert len(mina_auth.generate_hmac_secret()) == 64

    def test_generate_save_and_load(self, tmp_path):
        path = tmp_path / "credentials.env"
        gen = mina_auth.generate_and_save_credentials(path=path)
        loaded = mina_auth.load_credentials(path)
        assert loaded["api_key"] == gen["api_key"]
        assert loaded["hmac_secret"] == gen["hmac_secret"]

    def test_creds_file_is_chmod_600(self, tmp_path):
        path = tmp_path / "credentials.env"
        mina_auth.generate_and_save_credentials(path=path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_masking(self):
        assert mina_auth.mask_api_key("mina_sk_realsecret") == "mina_sk_********"
        assert mina_auth.mask_secret("abcdef") == "********"
        # Masks must never contain any key material
        assert "realsecret" not in mina_auth.mask_api_key("mina_sk_realsecret")

    def test_generate_returns_masked_variants(self, tmp_path):
        gen = mina_auth.generate_and_save_credentials(
            path=tmp_path / "credentials.env")
        assert gen["api_key_masked"] == "mina_sk_********"
        assert gen["hmac_secret_masked"] == "********"
        # The full values are present exactly here (one-time contract)
        assert gen["api_key"].startswith("mina_sk_")
        assert len(gen["hmac_secret"]) == 64

    def test_load_missing_file(self, tmp_path):
        assert mina_auth.load_credentials(tmp_path / "nope.env") is None

    def test_regeneration_rotates(self, tmp_path):
        path = tmp_path / "credentials.env"
        a = mina_auth.generate_and_save_credentials(path=path)
        b = mina_auth.generate_and_save_credentials(path=path)
        assert a["api_key"] != b["api_key"]
        assert mina_auth.load_credentials(path)["api_key"] == b["api_key"]


# ════════════════════════════════════════════════════════════════
# 4. WEB UI — full HTTP flow against a real server
# ════════════════════════════════════════════════════════════════

SETUP_TOKEN = "setup-token-xyz"
TEST_USER = "admin"
TEST_PASS = "secret12345"


@pytest.fixture
def ui_server(tmp_path):
    """Real HTTP server with the daemon handler + WebUI attached."""
    import mina_daemon as daemon
    import threading
    import socket

    auth_path = tmp_path / "auth.json"
    creds_path = tmp_path / "credentials.env"

    daemon.MinaHandler.api_key = ""       # unconfigured → setup mode
    daemon.MinaHandler.hmac_secret = ""

    def on_creds(api_key, hmac_secret):
        daemon.MinaHandler.api_key = api_key
        daemon.MinaHandler.hmac_secret = hmac_secret

    ui = mina_webui.WebUI(setup_token=SETUP_TOKEN,
                          on_credentials_generated=on_creds,
                          auth_path=auth_path, creds_path=creds_path)
    original_webui = daemon.WEBUI
    daemon.WEBUI = ui

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    srv = daemon.ThreadingHTTPServer(("127.0.0.1", port), daemon.MinaHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}", ui

    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)
    daemon.WEBUI = original_webui
    daemon.MinaHandler.api_key = ""
    daemon.MinaHandler.hmac_secret = ""


class Browser:
    """Tiny cookie-aware HTTP client for the web UI flow."""

    def __init__(self, base_url):
        self.base = base_url
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def get(self, path):
        req = urllib.request.Request(self.base + path)
        try:
            resp = self.opener.open(req, timeout=5)
            return resp.status, resp.read().decode(), resp.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), None

    def post(self, path, data):
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            self.base + path, data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            resp = self.opener.open(req, timeout=5)
            return resp.status, resp.read().decode(), resp.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), None


class TestWebUIFlow:
    def test_root_redirects_to_setup_when_unconfigured(self, ui_server):
        base, _ = ui_server
        b = Browser(base)
        status, _, final = b.get("/")
        assert status == 200
        assert final.endswith("/ui/setup")

    def test_setup_page_renders(self, ui_server):
        base, _ = ui_server
        status, body, _ = Browser(base).get("/ui/setup")
        assert status == 200
        assert "First-run setup" in body

    def test_setup_rejects_bad_token(self, ui_server):
        base, _ = ui_server
        b = Browser(base)
        status, body, _ = b.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": "wrong"})
        assert status == 401
        assert "token salah" in body.lower() or "setup token" in body.lower()

    def test_setup_rejects_mismatched_confirm(self, ui_server):
        base, _ = ui_server
        b = Browser(base)
        status, body, _ = b.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": "different123", "setup_token": SETUP_TOKEN})
        assert status == 400
        assert "tidak sama" in body

    def test_full_setup_login_dashboard_flow(self, ui_server):
        base, ui = ui_server
        b = Browser(base)

        # 1. setup → auto-login → dashboard
        status, _, final = b.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        assert status == 200
        assert final.endswith("/ui/dashboard")

        # 2. dashboard shows masked state + generate button
        status, body, _ = b.get("/ui/dashboard")
        assert status == 200
        assert "Generate API &amp; Secret Key" in body
        assert "Belum ada credentials" in body

        # 3. generate credentials (CSRF from the dashboard page).
        #    The 303 redirect is auto-followed → this response IS the
        #    one-time reveal page (exactly what a real browser shows).
        csrf = ui.sessions.get_field(
            next(iter(ui.sessions._sessions)), "csrf")
        status, reveal_body, final = b.post("/ui/generate", {"csrf": csrf})
        assert status == 200
        assert "notice=generated" in final

        # 4. ONE-TIME reveal — full secret visible exactly now
        assert "SEKALI INI" in reveal_body
        import re
        m = re.search(r'id="ak">([^<]+)<', reveal_body)
        assert m, "full api key not found in one-time reveal"
        full_key = m.group(1)
        assert full_key.startswith("mina_sk_") and len(full_key) > 20
        m2 = re.search(r'id="hs">([^<]+)<', reveal_body)
        assert m2 and len(m2.group(1)) == 64

        # 5. refresh — full secret GONE, only masks remain
        status, body2, _ = b.get("/ui/dashboard")
        assert status == 200
        assert full_key not in body2
        assert "mina_sk_********" in body2
        assert "SEKALI INI" not in body2

    def test_generate_requires_csrf(self, ui_server):
        base, ui = ui_server
        b = Browser(base)
        b.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        status, _, _ = b.post("/ui/generate", {"csrf": "wrong"})
        assert status == 403

    def test_generate_requires_login(self, ui_server):
        base, _ = ui_server
        # Configure the account first, then hit /ui/generate unauthenticated
        b1 = Browser(base)
        b1.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        b2 = Browser(base)
        status, _, final = b2.post("/ui/generate", {"csrf": "x"})
        assert final.endswith("/ui/login")

    def test_login_flow(self, ui_server):
        base, ui = ui_server
        # setup first
        b1 = Browser(base)
        b1.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        # fresh browser: login
        b2 = Browser(base)
        status, _, final = b2.post("/ui/login", {
            "username": TEST_USER, "password": TEST_PASS})
        assert final.endswith("/ui/dashboard")
        status, body, _ = b2.get("/ui/dashboard")
        assert TEST_USER in body

    def test_login_wrong_password(self, ui_server):
        base, _ = ui_server
        b1 = Browser(base)
        b1.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        b2 = Browser(base)
        status, body, _ = b2.post("/ui/login", {
            "username": TEST_USER, "password": "wrongpass123"})
        assert status == 401
        assert "salah" in body.lower()

    def test_login_rate_limited(self, ui_server):
        base, ui = ui_server
        b1 = Browser(base)
        b1.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        b2 = Browser(base)
        last_status = None
        for _ in range(7):
            last_status, _, _ = b2.post("/ui/login", {
                "username": TEST_USER, "password": "wrongpass123"})
        assert last_status == 429

    def test_logout_destroys_session(self, ui_server):
        base, _ = ui_server
        b = Browser(base)
        b.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        status, body, _ = b.get("/ui/dashboard")
        import re
        csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
        b.post("/ui/logout", {"csrf": csrf})
        status, _, final = b.get("/ui/dashboard")
        assert final.endswith("/ui/login")

    def test_setup_locked_after_configured(self, ui_server):
        base, _ = ui_server
        b = Browser(base)
        b.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        b2 = Browser(base)
        status, _, final = b2.get("/ui/setup")
        assert final.endswith("/ui/login")


class TestDaemonIntegration:
    def test_command_locked_until_credentials_exist(self, ui_server):
        """Unconfigured daemon: /command must 503, never execute."""
        base, _ = ui_server
        req = urllib.request.Request(
            base + "/command", data=b'{"action":"status"}',
            headers={"Authorization": "Bearer ",
                     "X-Mina-Signature": "x",
                     "Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            assert False, "should have been rejected"
        except urllib.error.HTTPError as e:
            assert e.code == 503
            assert json.loads(e.read())["error"] == "not_configured"

    def test_generate_hot_injects_into_daemon(self, ui_server):
        """After generate, the daemon accepts the NEW pair immediately."""
        base, ui = ui_server
        b = Browser(base)
        b.post("/ui/setup", {
            "username": TEST_USER, "password": TEST_PASS,
            "password_confirm": TEST_PASS, "setup_token": SETUP_TOKEN})
        csrf = ui.sessions.get_field(
            next(iter(ui.sessions._sessions)), "csrf")
        b.post("/ui/generate", {"csrf": csrf})

        import mina_daemon as daemon
        assert daemon.MinaHandler.api_key.startswith("mina_sk_")
        assert len(daemon.MinaHandler.hmac_secret) == 64

        # End-to-end: signed command with the new pair succeeds
        import send_command as sc
        result = sc.send_command(
            action="status", tunnel_url=base,
            api_key=daemon.MinaHandler.api_key,
            hmac_secret=daemon.MinaHandler.hmac_secret)
        assert result.get("ok") is True

    def test_health_reports_webui(self, ui_server):
        base, _ = ui_server
        resp = urllib.request.urlopen(base + "/health", timeout=5)
        data = json.loads(resp.read())
        assert data["webui_enabled"] is True


# ════════════════════════════════════════════════════════════════
# 5. LOW-SPEC CONSTRAINTS
# ════════════════════════════════════════════════════════════════

class TestLowSpecConstraints:
    def test_auth_module_imports_stdlib_only(self):
        """mina_auth must not depend on psutil/yaml/bcrypt/argon2."""
        src = (SCRIPTS_DIR / "mina_auth.py").read_text()
        for banned in ("import bcrypt", "import argon2", "import psutil",
                       "import yaml", "sqlite3"):
            assert banned not in src, f"heavy dependency found: {banned}"

    def test_webui_module_imports_stdlib_only(self):
        src = (SCRIPTS_DIR / "mina_webui.py").read_text()
        for banned in ("import psutil", "import yaml", "jinja2", "flask",
                       "fastapi"):
            assert banned not in src, f"heavy dependency found: {banned}"

    def test_no_background_threads_in_auth(self):
        """Sessions expire lazily — no timers/threads needed on weak CPU."""
        src = (SCRIPTS_DIR / "mina_auth.py").read_text()
        assert "threading.Thread" not in src

    def test_iterations_configurable_for_weak_cpu(self):
        """MINA_AUTH_ITERATIONS lets low-spec machines dial PBKDF2 cost down."""
        src = (SCRIPTS_DIR / "mina_auth.py").read_text()
        assert "MINA_AUTH_ITERATIONS" in src

    def test_session_caps_are_bounded(self):
        """Default session count is small — bounded memory footprint."""
        store = mina_auth.SessionStore()
        assert store.max_sessions <= 20


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
