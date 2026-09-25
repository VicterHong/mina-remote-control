#!/usr/bin/env python3
"""
Mina Auth — lightweight username/password auth + credential generator.

Low-spec design (Bay Trail-class low-spec class):
  - stdlib ONLY: hashlib.pbkdf2_hmac + secrets + json — no bcrypt/argon2,
    no database, no external service.
  - Storage = two tiny files under ~/.mina (chmod 600):
        auth.json        {"username", "password": {salt, hash, iterations}}
        credentials.env  MINA_API_KEY / MINA_HMAC_SECRET
  - Sessions live in memory (capped, lazy expiry) — zero disk churn,
    no background threads.
  - PBKDF2 iterations are configurable (default 100k ≈ 0.1–0.4 s on
    Bay Trail, and only paid at login).

One-time display contract (enforced by the daemon layer):
  generate_and_save_credentials() returns the FULL secret exactly once
  to the caller; every other read path exposes masked values only.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

MINA_HOME = Path.home() / ".mina"
AUTH_FILE = MINA_HOME / "auth.json"
CREDS_FILE = MINA_HOME / "credentials.env"

DEFAULT_ITERATIONS = int(os.environ.get("MINA_AUTH_ITERATIONS", "100000"))
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 8


def default_iterations() -> int:
    """PBKDF2 iterations — env MINA_AUTH_ITERATIONS wins (tests use small)."""
    return int(os.environ.get("MINA_AUTH_ITERATIONS", DEFAULT_ITERATIONS))


def _atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Write a file atomically with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ════════════════════════════════════════════════════════════════
# PASSWORD HASHING (PBKDF2-SHA256)
# ════════════════════════════════════════════════════════════════

def hash_password(password: str, salt: str | None = None,
                  iterations: int | None = None) -> dict:
    """Return a password record {algo, salt, iterations, hash}."""
    if salt is None:
        salt = secrets.token_hex(16)
    if iterations is None:
        iterations = default_iterations()
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return {"algo": "pbkdf2_sha256", "salt": salt,
            "iterations": iterations, "hash": dk.hex()}


def verify_password(password: str, record: dict) -> bool:
    """Constant-time password check against a stored record."""
    try:
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(record["salt"]), int(record["iterations"]))
        return _hmac.compare_digest(dk.hex(), record["hash"])
    except Exception:
        return False


_DUMMY_RECORD: dict | None = None


def _dummy_verify(password: str) -> None:
    """Burn one PBKDF2 cycle when the username doesn't match, so login
    timing does not reveal whether the username exists."""
    global _DUMMY_RECORD
    if _DUMMY_RECORD is None:
        _DUMMY_RECORD = hash_password("x" * 24, iterations=default_iterations())
    verify_password(password, _DUMMY_RECORD)


# ════════════════════════════════════════════════════════════════
# USER STORE (auth.json)
# ════════════════════════════════════════════════════════════════

def load_auth(path: Path | None = None) -> dict | None:
    path = path or AUTH_FILE
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or "username" not in data:
            return None
        return data
    except Exception:
        return None


def is_configured(path: Path | None = None) -> bool:
    return load_auth(path) is not None


def validate_username(username: str) -> str | None:
    """Return an error string, or None if valid."""
    if not username or not USERNAME_RE.match(username):
        return ("Username harus 3-32 karakter, hanya huruf/angka/._-")
    return None


def validate_password(password: str) -> str | None:
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password minimal {MIN_PASSWORD_LENGTH} karakter"
    if len(password) > 256:
        return "Password maksimal 256 karakter"
    return None


def set_password(username: str, password: str,
                 iterations: int | None = None,
                 path: Path | None = None) -> dict:
    """Create/overwrite the user record (atomic, chmod 600)."""
    path = path or AUTH_FILE
    record = {
        "username": username,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "password": hash_password(password, iterations=iterations),
    }
    _atomic_write(path, json.dumps(record, indent=2))
    return record


def check_password(username: str, password: str,
                   path: Path | None = None) -> bool:
    """Verify username + password (timing-equalised on username miss)."""
    record = load_auth(path)
    if not record:
        _dummy_verify(password)
        return False
    if not _hmac.compare_digest(str(record.get("username", "")),
                                str(username)):
        _dummy_verify(password)
        return False
    return verify_password(password, record.get("password") or {})


# ════════════════════════════════════════════════════════════════
# SESSIONS (in-memory, capped, lazy expiry — no threads)
# ════════════════════════════════════════════════════════════════

class SessionStore:
    """Thread-safe session store with idle + absolute timeouts."""

    def __init__(self, ttl_seconds: int = 1800,
                 absolute_seconds: int = 43200,
                 max_sessions: int = 10):
        self.ttl = int(ttl_seconds)
        self.absolute = int(absolute_seconds)
        self.max_sessions = int(max_sessions)
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, username: str) -> dict:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            self._prune(now)
            if len(self._sessions) >= self.max_sessions:
                oldest = min(self._sessions,
                             key=lambda t: self._sessions[t]["last_seen"])
                self._sessions.pop(oldest, None)
            session = {"token": token, "csrf": csrf, "username": username,
                       "created": now, "last_seen": now}
            self._sessions[token] = session
        return dict(session)

    def get(self, token: str | None) -> dict | None:
        if not token:
            return None
        now = time.time()
        with self._lock:
            s = self._sessions.get(token)
            if not s:
                return None
            if (now - s["last_seen"] > self.ttl
                    or now - s["created"] > self.absolute):
                self._sessions.pop(token, None)
                return None
            s["last_seen"] = now
            return dict(s)

    def get_field(self, token: str, key: str):
        """Read an extra session value without consuming it."""
        with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return None
            return s.get(key)

    def destroy(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def set_field(self, token: str, key: str, value) -> None:
        """Attach an extra value to a live session (e.g. pending reveal)."""
        with self._lock:
            s = self._sessions.get(token)
            if s is not None:
                s[key] = value

    def pop_field(self, token: str, key: str):
        """Remove and return an extra session value (one-time semantics)."""
        with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return None
            return s.pop(key, None)

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _prune(self, now: float) -> None:
        expired = [t for t, s in self._sessions.items()
                   if now - s["last_seen"] > self.ttl
                   or now - s["created"] > self.absolute]
        for t in expired:
            self._sessions.pop(t, None)


class AttemptLimiter:
    """Sliding-window failure limiter (login brute-force guard)."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300,
                 max_keys: int = 64):
        self.max_attempts = int(max_attempts)
        self.window = int(window_seconds)
        self.max_keys = int(max_keys)
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            self._prune(now)
            hits = self._hits.get(key)
            if hits is None:
                return True
            return len(hits) < self.max_attempts

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._prune(now)
            if len(self._hits) >= self.max_keys and key not in self._hits:
                oldest = min(self._hits, key=lambda k: self._hits[k][-1])
                self._hits.pop(oldest, None)
            self._hits.setdefault(key, deque(maxlen=self.max_attempts + 4))
            self._hits[key].append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        empty = []
        for k, hits in self._hits.items():
            while hits and hits[0] < cutoff:
                hits.popleft()
            if not hits:
                empty.append(k)
        for k in empty:
            self._hits.pop(k, None)


# ════════════════════════════════════════════════════════════════
# CREDENTIAL GENERATOR (API key + HMAC secret)
# ════════════════════════════════════════════════════════════════

def generate_api_key() -> str:
    return "mina_sk_" + secrets.token_urlsafe(32)


def generate_hmac_secret() -> str:
    return secrets.token_hex(32)


def mask_api_key(_api_key: str | None) -> str:
    """Always show the same fixed mask — never leak key material."""
    return "mina_sk_********"


def mask_secret(_secret: str | None) -> str:
    return "********"


def load_credentials(path: Path | None = None) -> dict | None:
    """Parse ~/.mina/credentials.env → dict, or None if absent."""
    path = path or CREDS_FILE
    if not path.exists():
        return None
    out: dict = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"').strip("'")
    except Exception:
        return None
    if not out.get("MINA_API_KEY") or not out.get("MINA_HMAC_SECRET"):
        return None
    return {
        "api_key": out["MINA_API_KEY"],
        "hmac_secret": out["MINA_HMAC_SECRET"],
        "generated_at": out.get("MINA_CREDENTIALS_GENERATED_AT"),
    }


def save_credentials(api_key: str, hmac_secret: str,
                     generated_at: str | None = None,
                     path: Path | None = None) -> None:
    """Persist credentials atomically with chmod 600."""
    path = path or CREDS_FILE
    ts = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _atomic_write(path,
                  "# Mina credentials — generated via web UI.\n"
                  "# chmod 600. Old keys stop working the moment a new\n"
                  "# pair is generated (hot-injected into the daemon).\n"
                  f"MINA_API_KEY={api_key}\n"
                  f"MINA_HMAC_SECRET={hmac_secret}\n"
                  f"MINA_CREDENTIALS_GENERATED_AT={ts}\n")


def generate_and_save_credentials(path: Path | None = None) -> dict:
    """Generate a fresh pair, persist it, return full + masked values.

    The full values are returned ONCE — callers must show them one time
    only and never persist them anywhere else.
    """
    api_key = generate_api_key()
    hmac_secret = generate_hmac_secret()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_credentials(api_key, hmac_secret, generated_at, path)
    return {
        "api_key": api_key,
        "hmac_secret": hmac_secret,
        "generated_at": generated_at,
        "api_key_masked": mask_api_key(api_key),
        "hmac_secret_masked": mask_secret(hmac_secret),
    }
