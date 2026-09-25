#!/usr/bin/env python3
"""
Mina Web UI — lightweight login, setup and credential-generator pages.

Served by the daemon itself (same process, same port) — no extra service,
no template engine, no JS framework. stdlib only.

Routes (all under /ui/):
    GET  /ui/setup       first-run: create the admin account
                         (requires the one-time setup token printed in the
                          daemon log — prevents remote claim via tunnel)
    POST /ui/setup       create account → auto-login → dashboard
    GET  /ui/login       login form
    POST /ui/login       verify (rate-limited) → session cookie
    GET  /ui/dashboard   masked keys + "Generate API & Secret Key"
    POST /ui/generate    rotate credentials, hot-inject into the daemon,
                         arm the ONE-TIME reveal for this session
    POST /ui/logout      destroy session
    GET  /               redirect → setup | dashboard | login

One-time display contract:
    After POST /ui/generate the FULL api key + hmac secret are rendered
    exactly once (first dashboard render in that session), then dropped
    from the session. Every later render — refresh, re-login, another
    browser — shows only masks (mina_sk_******** / ********).

Low-spec notes: in-memory sessions (capped), no threads, no polling,
atomic chmod-600 storage via mina_auth.
"""
from __future__ import annotations

import hmac as _hmac
import html
import urllib.parse
from http.cookies import SimpleCookie
from pathlib import Path

import mina_auth

COOKIE_NAME = "mina_session"
MAX_FORM_BYTES = 64 * 1024  # low-spec cap on POST bodies

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
       background:#0d1117; color:#e6edf3; margin:0; padding:24px;
       display:flex; justify-content:center; }
.wrap { width:100%; max-width:560px; }
h1 { font-size:1.25rem; margin:0 0 4px; }
.sub { color:#8b949e; font-size:.82rem; margin-bottom:22px; }
.card { background:#161b22; border:1px solid #30363d; border-radius:10px;
        padding:20px; margin-bottom:16px; }
label { display:block; font-size:.78rem; color:#8b949e; margin:14px 0 6px;
        text-transform:uppercase; letter-spacing:.06em; }
input[type=text], input[type=password] {
        width:100%; padding:10px 12px; border-radius:8px;
        border:1px solid #30363d; background:#0d1117; color:#e6edf3;
        font:inherit; font-size:.9rem; }
input:focus { outline:none; border-color:#58a6ff; }
button { margin-top:18px; width:100%; padding:11px; border:none;
         border-radius:8px; background:#238636; color:#fff; font:inherit;
         font-size:.9rem; font-weight:600; cursor:pointer; }
button:hover { background:#2ea043; }
button.secondary { background:#21262d; border:1px solid #30363d; }
button.secondary:hover { background:#30363d; }
.err { background:#3d1418; border:1px solid #f85149; color:#ff7b72;
       border-radius:8px; padding:10px 12px; font-size:.82rem;
       margin-bottom:14px; }
.ok { background:#0f2f1a; border:1px solid #2ea043; color:#7ee787;
      border-radius:8px; padding:10px 12px; font-size:.82rem;
      margin-bottom:14px; }
.warn { background:#2d2305; border:1px solid #d29922; color:#e3b341;
        border-radius:8px; padding:10px 12px; font-size:.82rem;
        margin-bottom:14px; }
.kv { display:flex; justify-content:space-between; gap:12px;
      padding:9px 0; border-bottom:1px solid #21262d; font-size:.85rem; }
.kv:last-child { border-bottom:none; }
.kv .k { color:#8b949e; }
.kv .v { text-align:right; word-break:break-all; }
.secret { background:#0d1117; border:1px dashed #d29922; border-radius:8px;
          padding:12px; margin:10px 0; font-size:.82rem; word-break:break-all;
          user-select:all; }
.secret .tag { color:#d29922; font-size:.72rem; display:block;
               margin-bottom:4px; letter-spacing:.06em; }
.reveal { border:1px solid #d29922; background:#1c1a10;
          border-radius:10px; padding:18px; margin-bottom:16px; }
.reveal h2 { margin:0 0 6px; font-size:.95rem; color:#e3b341; }
.reveal p { font-size:.8rem; color:#8b949e; margin:6px 0 0; }
.mask { color:#8b949e; }
a { color:#58a6ff; }
form.inline { display:inline; }
form.inline button { width:auto; margin:0; padding:7px 14px; font-size:.8rem; }
.topbar { display:flex; justify-content:space-between; align-items:center;
          margin-bottom:18px; }
.badge { font-size:.72rem; padding:3px 9px; border-radius:99px;
         border:1px solid #30363d; color:#8b949e; }
"""


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{html.escape(title)} — MINA</title><style>{_CSS}</style></head>
<body><div class="wrap">{body}</div></body></html>"""


# ── Page renderers ───────────────────────────────────────────────

def render_login(error: str | None = None) -> str:
    err = f'<div class="err">{html.escape(error)}</div>' if error else ""
    return _page("Login", f"""
<h1>⚡ MINA</h1>
<div class="sub">Local system &amp; hardware control — sign in</div>
<div class="card">
  {err}
  <form method="post" action="/ui/login">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" autocomplete="username"
           autofocus required maxlength="32">
    <label for="p">Password</label>
    <input id="p" name="password" type="password"
           autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</div>""")


def render_setup(error: str | None = None, need_token: bool = True) -> str:
    err = f'<div class="err">{html.escape(error)}</div>' if error else ""
    token_field = """
    <label for="t">Setup token</label>
    <input id="t" name="setup_token" type="text" required
           placeholder="from daemon log: journalctl -u mina-daemon">
    <div class="sub" style="margin:8px 0 0">Printed once at daemon startup.
    Prevents remote claim of the admin account through a tunnel.</div>
""" if need_token else ""
    return _page("Setup", f"""
<h1>⚡ MINA — First-run setup</h1>
<div class="sub">Create the admin account (stored as a PBKDF2 hash in
~/.mina/auth.json — no database)</div>
<div class="card">
  {err}
  <form method="post" action="/ui/setup">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" autofocus required
           minlength="3" maxlength="32" pattern="[A-Za-z0-9_.-]+">
    <label for="p">Password (min 8 chars)</label>
    <input id="p" name="password" type="password" required minlength="8">
    <label for="p2">Confirm password</label>
    <input id="p2" name="password_confirm" type="password" required
           minlength="8">
    {token_field}
    <button type="submit">Create account</button>
  </form>
</div>""")


def render_dashboard(username: str, creds: dict | None,
                     reveal: dict | None = None,
                     notice: str | None = None,
                     csrf: str = "") -> str:
    """Dashboard. `reveal` non-None => ONE-TIME full-secret display."""
    esc = html.escape
    notice_html = ""
    if notice == "generated":
        notice_html = ('<div class="ok">✓ Credentials baru dibuat dan langsung '
                       'disuntikkan ke daemon. Salin sekarang — lihat '
                       'peringatan di bawah.</div>')

    if reveal:
        reveal_html = f"""
<div class="reveal">
  <h2>🔑 Secret key — ditampilkan SEKALI INI saja</h2>
  <p>Salin sekarang. Begitu halaman di-refresh atau ditutup, nilai penuh
     tidak akan pernah ditampilkan lagi (hanya mask).</p>
  <div class="secret"><span class="tag">API KEY</span>
    <span id="ak">{esc(reveal['api_key'])}</span></div>
  <div class="secret"><span class="tag">HMAC SECRET</span>
    <span id="hs">{esc(reveal['hmac_secret'])}</span></div>
  <button class="secondary" onclick="copyAll()">Copy both</button>
  <p>Generated: {esc(reveal['generated_at'])} · Gunakan nilai ini di
     Hermes side (send_command.py / .env laptop lain).</p>
</div>
<script>
function copyAll() {{
  const t = "MINA_API_KEY=" + document.getElementById('ak').textContent +
            "\\nMINA_HMAC_SECRET=" + document.getElementById('hs').textContent;
  navigator.clipboard.writeText(t).then(() => {{
    document.querySelector('.reveal button').textContent = "Copied ✓";
  }});
}}
</script>"""
    else:
        reveal_html = ""

    if creds:
        creds_html = f"""
  <div class="kv"><span class="k">API key</span>
    <span class="v mask">{esc(creds['api_key_masked'])}</span></div>
  <div class="kv"><span class="k">HMAC secret</span>
    <span class="v mask">{esc(creds['hmac_secret_masked'])}</span></div>
  <div class="kv"><span class="k">Generated</span>
    <span class="v">{esc(creds.get('generated_at') or 'unknown')}</span></div>"""
        gen_button = f"""
  <form method="post" action="/ui/generate">
    <input type="hidden" name="csrf" value="{esc(csrf)}">
    <button type="submit"
      onclick="return confirm('Rotate credentials? The OLD key stops working immediately and the new secret is shown only once.')">
      ⟳ Generate API &amp; Secret Key</button>
  </form>
  <div class="sub" style="margin:10px 0 0">Rotasi: kunci lama langsung
  tidak berlaku. Secret baru ditampilkan satu kali.</div>"""
    else:
        creds_html = """
  <div class="warn">Belum ada credentials. Endpoint /command dinonaktifkan
  sampai Anda generate di bawah.</div>"""
        gen_button = f"""
  <form method="post" action="/ui/generate">
    <input type="hidden" name="csrf" value="{esc(csrf)}">
    <button type="submit">⚡ Generate API &amp; Secret Key</button>
  </form>"""

    return _page("Dashboard", f"""
<div class="topbar">
  <div><h1>⚡ MINA</h1>
  <div class="sub" style="margin:0">signed in as {esc(username)}</div></div>
  <form class="inline" method="post" action="/ui/logout">
    <input type="hidden" name="csrf" value="{esc(csrf)}">
    <button class="secondary" type="submit">Logout</button>
  </form>
</div>
{notice_html}
{reveal_html}
<div class="card">
  <div class="kv"><span class="k">Credentials</span>
    <span class="v"><span class="badge">stored ~/.mina/credentials.env</span></span></div>
  {creds_html}
</div>
<div class="card">
  {gen_button}
</div>
<div class="card">
  <div class="kv"><span class="k">Web UI</span>
    <span class="v">127.0.0.1 only (bind address)</span></div>
  <div class="kv"><span class="k">Sessions</span>
    <span class="v">in-memory, idle timeout 30 min</span></div>
  <div class="kv"><span class="k">Storage</span>
    <span class="v">auth.json (PBKDF2-SHA256) · chmod 600</span></div>
</div>""")


# ════════════════════════════════════════════════════════════════
# WebUI router — the daemon delegates /ui/* + / to this class
# ════════════════════════════════════════════════════════════════

class WebUI:
    """Routes GET/POST for the web UI. Never raises to the caller."""

    def __init__(self, setup_token: str = "",
                 on_credentials_generated=None,
                 auth_path: Path | None = None,
                 creds_path: Path | None = None,
                 session_ttl: int = 1800):
        self.sessions = mina_auth.SessionStore(ttl_seconds=session_ttl)
        self.limiter = mina_auth.AttemptLimiter()
        self.setup_token = setup_token
        self.on_credentials_generated = on_credentials_generated
        self.auth_path = auth_path
        self.creds_path = creds_path

    # ── helpers ──────────────────────────────────────────────────

    def _configured(self) -> bool:
        return mina_auth.is_configured(self.auth_path)

    def _session(self, handler) -> dict | None:
        return self.sessions.get(self._cookie_token(handler))

    @staticmethod
    def _cookie_token(handler) -> str | None:
        raw = handler.headers.get("Cookie", "")
        if not raw:
            return None
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
            morsel = cookie.get(COOKIE_NAME)
            return morsel.value if morsel else None
        except Exception:
            return None

    @staticmethod
    def _send_html(handler, code: int, text: str,
                   headers: dict | None = None) -> None:
        body = text.encode("utf-8")
        handler.send_response(code)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("X-Frame-Options", "DENY")
        handler.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()
        handler.wfile.write(body)

    @staticmethod
    def _redirect(handler, location: str, headers: dict | None = None) -> None:
        handler.send_response(303)
        handler.send_header("Location", location)
        handler.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        handler.end_headers()

    @staticmethod
    def _read_form(handler) -> dict | None:
        """Parse a urlencoded POST body (capped). None on oversize/bad input."""
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_FORM_BYTES:
            return None
        try:
            body = handler.rfile.read(length).decode("utf-8", errors="replace")
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            return {k: v[0] for k, v in parsed.items()}
        except Exception:
            return None

    def _set_cookie(self, handler, token: str) -> dict:
        return {"Set-Cookie": f"{COOKIE_NAME}={token}; HttpOnly; "
                              f"SameSite=Strict; Path=/; Max-Age=43200"}

    def _clear_cookie(self) -> dict:
        return {"Set-Cookie": f"{COOKIE_NAME}=deleted; HttpOnly; "
                              f"SameSite=Strict; Path=/; Max-Age=0"}

    @staticmethod
    def _client_key(handler) -> str:
        try:
            return handler.client_address[0]
        except Exception:
            return "unknown"

    @staticmethod
    def _csrf_ok(form: dict, session: dict) -> bool:
        return _hmac.compare_digest(form.get("csrf", ""),
                                    session.get("csrf", ""))

    # ── GET routing ──────────────────────────────────────────────

    def route_get(self, handler) -> bool:
        """Handle web UI GET paths. Returns True when the request is done."""
        try:
            path = urllib.parse.urlsplit(handler.path).path
            if path == "/":
                return self._root(handler)
            if path == "/ui/login":
                return self._get_login(handler)
            if path == "/ui/setup":
                return self._get_setup(handler)
            if path == "/ui/dashboard":
                return self._get_dashboard(handler)
            if path.startswith("/ui/"):
                self._send_html(handler, 404,
                                _page("Not found", "<h1>404</h1>"))
                return True
            return False  # not ours (e.g. /health)
        except Exception:
            try:
                self._send_html(handler, 500,
                                _page("Error", "<h1>Internal error</h1>"))
            except Exception:
                pass
            return True

    def _root(self, handler) -> bool:
        if not self._configured():
            self._redirect(handler, "/ui/setup")
        elif self._session(handler):
            self._redirect(handler, "/ui/dashboard")
        else:
            self._redirect(handler, "/ui/login")
        return True

    def _get_login(self, handler) -> bool:
        if not self._configured():
            self._redirect(handler, "/ui/setup")
            return True
        if self._session(handler):
            self._redirect(handler, "/ui/dashboard")
            return True
        self._send_html(handler, 200, render_login())
        return True

    def _get_setup(self, handler) -> bool:
        if self._configured():
            self._redirect(handler, "/ui/login")
            return True
        self._send_html(handler, 200,
                        render_setup(need_token=bool(self.setup_token)))
        return True

    def _get_dashboard(self, handler) -> bool:
        session = self._session(handler)
        if not session:
            self._redirect(handler, "/ui/login")
            return True
        # ONE-TIME reveal: consume the armed secret on this render
        reveal = self.sessions.pop_field(session["token"], "pending_reveal")
        creds = mina_auth.load_credentials(self.creds_path)
        notice = urllib.parse.parse_qs(
            urllib.parse.urlsplit(handler.path).query).get("notice", [None])[0]
        creds_view = None
        if creds:
            creds_view = {
                "api_key_masked": mina_auth.mask_api_key(creds["api_key"]),
                "hmac_secret_masked": mina_auth.mask_secret(
                    creds["hmac_secret"]),
                "generated_at": creds.get("generated_at"),
            }
        self._send_html(handler, 200, render_dashboard(
            session["username"], creds_view, reveal=reveal,
            notice=notice, csrf=session["csrf"]))
        return True

    # ── POST routing ─────────────────────────────────────────────

    def route_post(self, handler) -> bool:
        """Handle web UI POST paths. Returns True when the request is done."""
        try:
            path = urllib.parse.urlsplit(handler.path).path
            if path == "/ui/login":
                return self._post_login(handler)
            if path == "/ui/setup":
                return self._post_setup(handler)
            if path == "/ui/generate":
                return self._post_generate(handler)
            if path == "/ui/logout":
                return self._post_logout(handler)
            if path.startswith("/ui/"):
                self._send_html(handler, 404,
                                _page("Not found", "<h1>404</h1>"))
                return True
            return False
        except Exception:
            try:
                self._send_html(handler, 500,
                                _page("Error", "<h1>Internal error</h1>"))
            except Exception:
                pass
            return True

    def _post_setup(self, handler) -> bool:
        if self._configured():
            self._send_html(handler, 403,
                            _page("Forbidden",
                                  "<h1>Already configured</h1>"))
            return True
        form = self._read_form(handler)
        if form is None:
            self._send_html(handler, 400, render_setup("Invalid form"))
            return True
        if self.setup_token and not _hmac.compare_digest(
                form.get("setup_token", ""), self.setup_token):
            self._send_html(handler, 401,
                            render_setup("Setup token salah. Lihat log "
                                         "daemon (journalctl)."))
            return True
        username = form.get("username", "").strip()
        password = form.get("password", "")
        confirm = form.get("password_confirm", "")
        err = mina_auth.validate_username(username) or \
            mina_auth.validate_password(password)
        if err:
            self._send_html(handler, 400, render_setup(err))
            return True
        if password != confirm:
            self._send_html(handler, 400,
                            render_setup("Password dan konfirmasi tidak sama"))
            return True
        mina_auth.set_password(username, password, path=self.auth_path)
        session = self.sessions.create(username)
        self._redirect(handler, "/ui/dashboard",
                       headers=self._set_cookie(handler, session["token"]))
        return True

    def _post_login(self, handler) -> bool:
        if not self._configured():
            self._redirect(handler, "/ui/setup")
            return True
        form = self._read_form(handler)
        if form is None:
            self._send_html(handler, 400, render_login("Invalid form"))
            return True
        username = form.get("username", "").strip()
        password = form.get("password", "")
        ip_key = f"ip:{self._client_key(handler)}"
        user_key = f"user:{username.lower()}"
        if not (self.limiter.allow(ip_key) and self.limiter.allow(user_key)):
            self._send_html(handler, 429,
                            render_login("Terlalu banyak percobaan. "
                                         "Coba lagi beberapa menit."))
            return True
        if not mina_auth.check_password(username, password,
                                        path=self.auth_path):
            self.limiter.record_failure(ip_key)
            self.limiter.record_failure(user_key)
            self._send_html(handler, 401,
                            render_login("Username atau password salah"))
            return True
        self.limiter.reset(ip_key)
        self.limiter.reset(user_key)
        session = self.sessions.create(username)
        self._redirect(handler, "/ui/dashboard",
                       headers=self._set_cookie(handler, session["token"]))
        return True

    def _post_generate(self, handler) -> bool:
        session = self._session(handler)
        if not session:
            self._redirect(handler, "/ui/login")
            return True
        form = self._read_form(handler) or {}
        if not self._csrf_ok(form, session):
            self._send_html(handler, 403,
                            _page("Forbidden", "<h1>CSRF check failed</h1>"))
            return True
        generated = mina_auth.generate_and_save_credentials(self.creds_path)
        # Hot-inject: daemon accepts the new pair immediately
        if self.on_credentials_generated:
            try:
                self.on_credentials_generated(generated["api_key"],
                                              generated["hmac_secret"])
            except Exception:
                pass
        # Arm the ONE-TIME reveal for this session only
        self.sessions.set_field(session["token"], "pending_reveal", {
            "api_key": generated["api_key"],
            "hmac_secret": generated["hmac_secret"],
            "generated_at": generated["generated_at"],
        })
        self._redirect(handler, "/ui/dashboard?notice=generated")
        return True

    def _post_logout(self, handler) -> bool:
        session = self._session(handler)
        if session:
            form = self._read_form(handler) or {}
            if self._csrf_ok(form, session):
                self.sessions.destroy(session["token"])
        self._redirect(handler, "/ui/login",
                       headers=self._clear_cookie())
        return True
