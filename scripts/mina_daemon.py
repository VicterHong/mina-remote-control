#!/usr/bin/env python3
"""
Mina Local Daemon — runs on the user's laptop (Windows/Linux/macOS).

Receives signed command payloads from the Hermes server via HTTPS webhook,
verifies HMAC-SHA256 signature + API token, and executes allowlisted
system commands (shutdown, lock, sleep, run_script, etc.).

SECURITY:
  - Bearer token auth (MINA_API_KEY)
  - HMAC-SHA256 signature verification on every request body
  - Replay protection: timestamp must be within 5 minutes
  - Command allowlist: only actions in commands.yaml can execute
  - No shell injection: subprocess.run with arg arrays, shell=False
  - Scripts restricted to ~/.mina/scripts/ directory

USAGE:
  Linux/macOS:
    python3 mina_daemon.py

  Windows:
    python mina_daemon.py

  With custom config:
    python3 mina_daemon.py --port 8765 --api-key mina_sk_... --hmac-secret ...

  Install as service (Linux):
    See deployment guide — systemd unit file included.

  Install as service (Windows):
    Use NSSM or Task Scheduler — see deployment guide.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn

# ── Optional: psutil for status command ──────────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Optional: pyyaml for commands.yaml ───────────────────────────
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ── Web UI + auth modules (same directory; optional for bare installs) ──
try:
    import mina_auth
    import mina_webui
    HAS_WEBUI_MODULES = True
except ImportError:
    mina_auth = None
    mina_webui = None
    HAS_WEBUI_MODULES = False


# ════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════

DEFAULT_PORT = 8765
REPLAY_WINDOW_SECONDS = 300  # 5 minutes
RATE_LIMIT_WINDOW = 3600     # 1 hour
DESTRUCTIVE_CONFIRM_DELAY = 5  # seconds

# Resolve paths
MINA_HOME = Path.home() / ".mina"
SCRIPTS_DIR = MINA_HOME / "scripts"
LOG_DIR = MINA_HOME / "logs"
LOG_FILE = LOG_DIR / "mina_daemon.log"
SEEN_NONCES: deque[tuple[str, float]] = deque(maxlen=10000)
RATE_COUNTERS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=100))

# ── Logger setup ─────────────────────────────────────────────────
LOG_DIR.mkdir(parents=True, exist_ok=True)
SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("mina")
logger.setLevel(logging.DEBUG)
# Rotating log keeps disk usage bounded on small disks (low-spec profile)
from logging.handlers import RotatingFileHandler
fh = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=2)
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
fh.setFormatter(fmt)
ch.setFormatter(fmt)
logger.addHandler(fh)
logger.addHandler(ch)


# ════════════════════════════════════════════════════════════════
# COMMAND ALLOWLIST (built-in fallback if no YAML config)
# ════════════════════════════════════════════════════════════════

BUILTIN_COMMANDS = {
    "shutdown": {
        "windows": ["shutdown", "/s", "/t", "1"],
        "linux": ["systemctl", "poweroff"],
        "macos": ["shutdown", "-h", "now"],
        "destructive": True,
        "handler": None,
    },
    "restart": {
        "windows": ["shutdown", "/r", "/t", "1"],
        "linux": ["systemctl", "reboot"],
        "macos": ["shutdown", "-r", "now"],
        "destructive": True,
        "handler": None,
    },
    "sleep": {
        "windows": ["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"],
        "linux": ["systemctl", "suspend"],
        "macos": ["pmset", "sleepnow"],
        "destructive": False,
        "handler": None,
    },
    "hibernate": {
        "windows": ["shutdown", "/h"],
        "linux": ["systemctl", "hibernate"],
        "macos": ["pmset", "hibernatenow"],
        "destructive": False,
        "handler": None,
    },
    "lock": {
        "windows": ["rundll32.exe", "user32.dll,LockWorkStation"],
        # NOTE: 'lock-session' (no args) fails from a service context because
        # the daemon has no login session; 'lock-sessions' locks all sessions.
        "linux": ["loginctl", "lock-sessions"],
        "macos": ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"],
        "destructive": False,
        "handler": None,
    },
    "status": {
        "destructive": False,
        "handler": "status",
    },
    "screenshot": {
        "destructive": False,
        "handler": "screenshot",
    },
    "volume": {
        "windows": ["nircmd", "setsysvolume", "{arg}"],
        "linux": ["amixer", "set", "Master", "{arg}%"],
        "macos": ["osascript", "-e", "set volume output volume {arg}"],
        "destructive": False,
        "handler": None,
        "requires_args": True,
    },
    "run_script": {
        "destructive": False,
        "handler": "script",
        "requires_args": True,
    },
    # ── Power: Wake-on-LAN ────────────────────────────────────────
    "wake": {
        "destructive": False,
        "handler": "wake",
        "requires_args": True,
    },
    # ── Screen & GUI automation ───────────────────────────────────
    "open_app": {
        "destructive": False,
        "handler": "open_app",
        "requires_args": True,
    },
    "open_url": {
        "destructive": False,
        "handler": "open_url",
        "requires_args": True,
    },
    "dashboard": {
        "destructive": False,
        "handler": "dashboard",
    },
    "gui_type": {
        "destructive": False,
        "handler": "gui_type",
        "requires_args": True,
    },
    "gui_key": {
        "destructive": False,
        "handler": "gui_key",
        "requires_args": True,
    },
    "gui_click": {
        "destructive": False,
        "handler": "gui_click",
        "requires_args": True,
    },
}

RATE_LIMITS = {
    "shutdown": 2, "restart": 2, "sleep": 10, "hibernate": 5,
    "lock": 20, "status": 60, "screenshot": 10,
    "volume": 30, "run_script": 20,
    "wake": 10, "open_app": 20, "open_url": 20, "dashboard": 10,
    "gui_type": 30, "gui_key": 30, "gui_click": 30,
}


def load_commands_yaml() -> dict | None:
    """Load commands.yaml from skill config if available."""
    if not HAS_YAML:
        return None
    yaml_path = Path(__file__).parent.parent / "config" / "commands.yaml"
    if not yaml_path.exists():
        # Try ~/.hermes/skills/... path
        yaml_path = Path.home() / ".hermes" / "skills" / "system-control" / "mina-workspace" / "config" / "commands.yaml"
    if not yaml_path.exists():
        return None
    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        return data
    except Exception as e:
        logger.warning(f"Failed to load commands.yaml: {e}")
        return None


# ── Merge commands.yaml (allowlist config) into BUILTIN_COMMANDS ──
# commands.yaml, when present, refines the built-in allowlist (platform
# argv arrays, descriptions). Built-ins remain the fallback.
_YAML_COMMANDS = (load_commands_yaml() or {}).get("actions")
if isinstance(_YAML_COMMANDS, dict):
    for _name, _cfg in _YAML_COMMANDS.items():
        if not isinstance(_cfg, dict):
            continue
        _merged = dict(BUILTIN_COMMANDS.get(_name, {}))
        _merged.update(_cfg)
        BUILTIN_COMMANDS[_name] = _merged


def load_agent_config() -> dict:
    """Load mina.yaml (agent config: apps allowlist, devices registry)."""
    if not HAS_YAML:
        return {}
    for yaml_path in [
        Path(__file__).parent.parent / "config" / "mina.yaml",
        Path.home() / ".hermes" / "skills" / "system-control"
        / "mina-workspace" / "config" / "mina.yaml",
        Path.home() / ".mina" / "mina.yaml",
    ]:
        if yaml_path.exists():
            try:
                with open(yaml_path) as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logger.warning(f"Failed to load {yaml_path}: {e}")
    return {}


AGENT_CONFIG = load_agent_config()


# ════════════════════════════════════════════════════════════════
# PERFORMANCE PROFILE (low-spec friendly)
# Priority: environment variable > mina.yaml performance: > built-in
# default. Tuned for weak laptops (e.g. Bay Trail-class low-spec).
# ════════════════════════════════════════════════════════════════

_PERF = AGENT_CONFIG.get("performance") or {}
_TIER2_PERF = _PERF.get("tier2") or {}


def _perf_env(env_name: str, perf_key: str, default):
    """Resolve a performance knob: env var wins, then mina.yaml, then default."""
    val = os.environ.get(env_name)
    if val is None:
        val = _PERF.get(perf_key, default)
    return val


STATUS_CPU_SAMPLE_INTERVAL = float(
    _perf_env("MINA_STATUS_CPU_INTERVAL", "status_cpu_sample_interval_s", 0.5))
CMD_TIMEOUT_SECONDS = int(
    _perf_env("MINA_CMD_TIMEOUT", "cmd_timeout_s", 30))
DASHBOARD_REFRESH_SECONDS = int(
    _perf_env("MINA_DASHBOARD_REFRESH", "dashboard_refresh_s", 30))
TIER2_MIN_FREE_MB = int(os.environ.get(
    "MINA_TIER2_MIN_FREE_MB", _TIER2_PERF.get("min_free_memory_mb", 150)))
TIER2_MAX_FAILURES = int(os.environ.get(
    "MINA_TIER2_MAX_FAILURES", _TIER2_PERF.get("max_consecutive_failures", 2)))

_tier2_env = os.environ.get("MINA_TIER2")
if _tier2_env is not None:
    _tier2_enabled = _tier2_env.strip().lower() not in ("off", "0", "false", "no")
else:
    _tier2_enabled = bool(_TIER2_PERF.get("enabled", True))

# Circuit-breaker state for Tier-2 GUI automation
TIER2_STATE = {
    "enabled": _tier2_enabled,
    "failures": 0,
    "reason": None if _tier2_enabled else "tier2_disabled_by_config",
}


def tier2_available() -> tuple[bool, str | None]:
    """Return (available, reason). Never raises."""
    if not TIER2_STATE["enabled"]:
        return False, TIER2_STATE["reason"] or "tier2_disabled"
    return True, None


def tier2_force_disable(reason: str) -> None:
    """Disable Tier-2 GUI automation for the daemon's lifetime."""
    TIER2_STATE["enabled"] = False
    TIER2_STATE["reason"] = reason


def tier2_record_failure(reason: str) -> None:
    """Count a Tier-2 failure; open the circuit after TIER2_MAX_FAILURES."""
    TIER2_STATE["failures"] += 1
    if TIER2_STATE["failures"] >= TIER2_MAX_FAILURES and TIER2_STATE["enabled"]:
        tier2_force_disable(reason)
        logger.warning(
            f"Tier-2 GUI automation disabled after {TIER2_STATE['failures']} "
            f"failure(s) ({reason}) — Tier-1 capabilities remain active")


def tier2_record_success() -> None:
    TIER2_STATE["failures"] = 0


def memory_guard() -> dict:
    """Pre-flight RAM check: preemptively disable Tier-2 when RAM is low.

    Keeps the daemon (Tier-1) safe on machines like low-spec machines where a
    pyautogui import could push the system into swap / freeze.
    """
    report = {"checked": False, "available_mb": None, "action": "none"}
    if not HAS_PSUTIL:
        return report
    try:
        avail_mb = psutil.virtual_memory().available / (1024 ** 2)
    except Exception:
        return report
    report["checked"] = True
    report["available_mb"] = round(avail_mb)
    if avail_mb < TIER2_MIN_FREE_MB and TIER2_STATE["enabled"]:
        tier2_force_disable("tier2_disabled_low_memory")
        report["action"] = "tier2_disabled_low_memory"
    return report


# ════════════════════════════════════════════════════════════════
# PLATFORM DETECTION
# ════════════════════════════════════════════════════════════════

def get_platform() -> str:
    """Return 'windows', 'linux', or 'macos'."""
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


PLATFORM = get_platform()


# ════════════════════════════════════════════════════════════════
# SECURITY: HMAC + REPLAY PROTECTION
# ════════════════════════════════════════════════════════════════

def verify_hmac(payload_bytes: bytes, signature: str, hmac_secret: str) -> bool:
    """Verify HMAC-SHA256 signature using timing-safe comparison."""
    expected = hmac.new(
        hmac_secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def check_replay(nonce: str, timestamp: int) -> bool:
    """Check for replay attacks — nonce must be unique and timestamp recent."""
    now = time.time()
    # Prune old nonces
    while SEEN_NONCES and now - SEEN_NONCES[0][1] > REPLAY_WINDOW_SECONDS * 2:
        SEEN_NONCES.popleft()

    # Check timestamp window
    if abs(now - timestamp) > REPLAY_WINDOW_SECONDS:
        return False

    # Check nonce uniqueness
    for n, t in SEEN_NONCES:
        if n == nonce:
            return False  # Replay!

    SEEN_NONCES.append((nonce, now))
    return True


def check_rate_limit(action: str) -> bool:
    """Rate limit per action per hour."""
    now = time.time()
    counter = RATE_COUNTERS[action]
    # Prune old entries
    while counter and now - counter[0] > RATE_LIMIT_WINDOW:
        counter.popleft()
    limit = RATE_LIMITS.get(action, 10)
    if len(counter) >= limit:
        return False
    counter.append(now)
    return True


# ════════════════════════════════════════════════════════════════
# COMMAND EXECUTION
# ════════════════════════════════════════════════════════════════

def execute_subprocess(cmd_args: list[str]) -> dict:
    """Execute a subprocess command safely (shell=False always)."""
    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT_SECONDS,
            shell=False,  # NEVER True
        )
        return {
            "ok": True,
            "returncode": result.returncode,
            "stdout": result.stdout.strip()[:500],
            "stderr": result.stderr.strip()[:500],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout",
                "detail": f"Command timed out after {CMD_TIMEOUT_SECONDS}s"}
    except FileNotFoundError:
        return {"ok": False, "error": "not_found", "detail": f"Command not found: {cmd_args[0]}"}
    except Exception as e:
        return {"ok": False, "error": "execution_error", "detail": str(e)}


def execute_launcher(cmd_args: list[str]) -> dict:
    """Launch a GUI app OUTSIDE the daemon's cgroup.

    Why: under systemd with MemoryMax=100M, child processes inherit the
    cgroup limit. A browser (open_app/open_url/dashboard) would be
    OOM-killed inside that cgroup and could take the daemon down with it.
    On low-spec machines (low-spec laptop) we therefore detach GUI launchers via
    `systemd-run --user --scope` when the user manager is reachable;
    otherwise fall back to a plain detached Popen (no cgroup escape, but
    the daemon never crashes — the unit also sets OOMPolicy=continue).

    Returns quickly — launchers are fire-and-forget.
    """
    base = cmd_args
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if (PLATFORM == "linux" and shutil.which("systemd-run")
            and xdg and os.path.isdir(os.path.join(xdg, "systemd"))):
        base = ["systemd-run", "--user", "--scope", "--quiet"] + cmd_args
    try:
        proc = subprocess.Popen(
            base,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # detach from daemon's session/process group
            shell=False,
        )
        return {"ok": True, "pid": proc.pid, "command": cmd_args,
                "detached": base is not cmd_args}
    except FileNotFoundError:
        return {"ok": False, "error": "not_found",
                "detail": f"Command not found: {base[0]}"}
    except Exception as e:
        return {"ok": False, "error": "execution_error", "detail": str(e)}


def handle_status() -> dict:
    """Return system health status."""
    info = {
        "platform": PLATFORM,
        "hostname": platform.node(),
        "uptime": int(time.time() - psutil.boot_time()) if HAS_PSUTIL else "unknown",
    }
    if HAS_PSUTIL:
        # Short sample window keeps CPU load low on weak hardware
        info["cpu_percent"] = psutil.cpu_percent(interval=STATUS_CPU_SAMPLE_INTERVAL)
        mem = psutil.virtual_memory()
        info["memory_percent"] = mem.percent
        info["memory_total_gb"] = round(mem.total / (1024**3), 1)
        disk = psutil.disk_usage("/")
        info["disk_percent"] = round(disk.percent, 1)
        info["disk_total_gb"] = round(disk.total / (1024**3), 1)
    else:
        info["note"] = "psutil not installed — limited metrics"
    # Observability: current degradation state (Tier-2 circuit breaker)
    info["tier2_enabled"] = TIER2_STATE["enabled"]
    if not TIER2_STATE["enabled"] and TIER2_STATE["reason"]:
        info["tier2_reason"] = TIER2_STATE["reason"]
    return {"ok": True, "status": info}


def handle_screenshot() -> dict:
    """Capture a screenshot."""
    try:
        import importlib
        # Try platform-specific screenshot
        if PLATFORM == "linux":
            # Try scrot, then gnome-screenshot
            for cmd in [["scrot", "/tmp/mina_screenshot.png"],
                        ["gnome-screenshot", "-f", "/tmp/mina_screenshot.png"]]:
                r = subprocess.run(cmd, capture_output=True, timeout=10, shell=False)
                if r.returncode == 0:
                    return {"ok": True, "screenshot": "/tmp/mina_screenshot.png"}
            return {"ok": False, "error": "no_screenshot_tool", "detail": "Install scrot or gnome-screenshot"}
        elif PLATFORM == "windows":
            # Use Pillow + ImageGrab
            from PIL import ImageGrab
            img = ImageGrab.grab()
            path = str(Path.home() / "mina_screenshot.png")
            img.save(path)
            return {"ok": True, "screenshot": path}
        elif PLATFORM == "macos":
            r = subprocess.run(["screencapture", "/tmp/mina_screenshot.png"],
                              capture_output=True, timeout=10, shell=False)
            return {"ok": True, "screenshot": "/tmp/mina_screenshot.png"} if r.returncode == 0 else {"ok": False, "error": "screencapture_failed"}
    except Exception as e:
        return {"ok": False, "error": "screenshot_error", "detail": str(e)}


def handle_script(script_name: str) -> dict:
    """Run a whitelisted script from ~/.mina/scripts/."""
    # Sanitize script name — only alphanumeric, underscore, hyphen
    if not re.match(r"^[a-zA-Z0-9_-]+$", script_name):
        return {"ok": False, "error": "invalid_script_name",
                "detail": "Script name must be alphanumeric/underscore/hyphen only"}

    scripts_dir = SCRIPTS_DIR
    # Find script with allowed extensions
    for ext in [".sh", ".bat", ".ps1", ".py"]:
        candidate = scripts_dir / f"{script_name}{ext}"
        if candidate.exists() and candidate.is_file():
            # Verify it's within the scripts directory (no path traversal)
            try:
                candidate.resolve().relative_to(scripts_dir.resolve())
            except ValueError:
                return {"ok": False, "error": "path_traversal_blocked",
                        "detail": "Script must be in ~/.mina/scripts/"}

            # Execute based on extension
            if ext == ".py":
                cmd = [sys.executable, str(candidate)]
            elif ext == ".sh" and PLATFORM != "windows":
                cmd = ["bash", str(candidate)]
            elif ext == ".bat" and PLATFORM == "windows":
                cmd = ["cmd", "/c", str(candidate)]
            elif ext == ".ps1" and PLATFORM == "windows":
                cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(candidate)]
            else:
                return {"ok": False, "error": "unsupported_extension",
                        "detail": f"{ext} not supported on {PLATFORM}"}

            result = execute_subprocess(cmd)
            result["script"] = str(candidate)
            return result

    return {"ok": False, "error": "script_not_found",
            "detail": f"No script '{script_name}' in {scripts_dir}. "
                      f"Expected: {script_name}.sh, .bat, .ps1, or .py"}


# ── Power: Wake-on-LAN handler ───────────────────────────────────

def handle_wake(device_name: str) -> dict:
    """Send a WoL magic packet to a registered device (or raw MAC)."""
    try:
        import importlib.util
        wol_path = Path(__file__).parent / "wol.py"
        spec = importlib.util.spec_from_file_location("mina_wol", wol_path)
        wol = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wol)
    except Exception as e:
        return {"ok": False, "error": "wol_module_error", "detail": str(e)}

    # Accept raw MAC addresses directly, otherwise look up the registry.
    if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", device_name):
        return wol.send_magic_packet(device_name)
    return wol.wake_device(device_name)


# ── Screen & GUI automation handlers ─────────────────────────────

def _load_gui_module():
    """Import gui_automation.py lazily from the scripts dir."""
    import importlib.util
    gui_path = Path(__file__).parent / "gui_automation.py"
    spec = importlib.util.spec_from_file_location("mina_gui", gui_path)
    gui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gui)
    return gui


def handle_open_app(app_name: str) -> dict:
    """Open an allowlisted app (apps: in mina.yaml)."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", app_name):
        return {"ok": False, "error": "invalid_app_name",
                "detail": "App name must be alphanumeric/underscore/hyphen"}
    apps = (AGENT_CONFIG.get("apps") or {})
    spec = apps.get(app_name)
    if not spec:
        return {"ok": False, "error": "unknown_app",
                "detail": f"'{app_name}' not in apps allowlist "
                          f"(known: {', '.join(sorted(apps)) or 'none'})"}
    try:
        gui = _load_gui_module()
    except Exception as e:
        return {"ok": False, "error": "gui_module_error", "detail": str(e)}
    cmd = gui.open_app_cmd(spec if isinstance(spec, dict) else {})
    if not cmd:
        return {"ok": False, "error": "unsupported_platform",
                "detail": f"app '{app_name}' has no command for {PLATFORM}"}
    result = execute_launcher(cmd)
    result["app"] = app_name
    result["command"] = cmd
    return result


def handle_open_url(url: str) -> dict:
    """Open a URL in the default browser (http/https/file only)."""
    try:
        gui = _load_gui_module()
    except Exception as e:
        return {"ok": False, "error": "gui_module_error", "detail": str(e)}
    cmd = gui.open_url_cmd(url)
    if not cmd:
        return {"ok": False, "error": "invalid_url",
                "detail": "URL must start with http://, https://, or file://"}
    result = execute_launcher(cmd)
    result["url"] = url
    return result


def handle_dashboard() -> dict:
    """Generate the monitoring dashboard and open it in the browser.

    Two-phase for low-spec safety:
      1. generate HTML inside the daemon cgroup (lightweight);
      2. launch the browser detached (execute_launcher) so it never
         inherits the daemon's MemoryMax cgroup limit.
    """
    dash = Path(__file__).parent / "dashboard.py"
    if not dash.exists():
        return {"ok": False, "error": "dashboard_missing",
                "detail": f"dashboard.py not found at {dash}"}
    out = Path.home() / ".mina" / "dashboard.html"
    gen = execute_subprocess(
        [sys.executable, str(dash), "--out", str(out),
         "--interval", str(DASHBOARD_REFRESH_SECONDS)])
    if gen.get("returncode", 0) != 0:
        return {"ok": False, "error": "dashboard_generation_failed",
                "detail": gen.get("stderr") or gen.get("error", "unknown"),
                "generation": gen}
    result = {"ok": True, "action": "dashboard", "dashboard": str(out),
              "refresh_interval_s": DASHBOARD_REFRESH_SECONDS,
              "generation": gen}
    try:
        gui = _load_gui_module()
        cmd = gui.open_url_cmd(out.as_uri())
    except Exception as e:
        cmd = None
        result["open_error"] = str(e)
    if cmd:
        opened = execute_launcher(cmd)
        result["opened"] = bool(opened.get("ok"))
        result["detached"] = opened.get("detached", False)
        if not opened.get("ok"):
            result["open_error"] = opened.get("error")
    else:
        result["opened"] = False
        result.setdefault("open_error", "cannot_build_launcher")
    return result


# ── Tier-2 gate (graceful degradation) ───────────────────────────

def _tier2_gate() -> dict | None:
    """Return an error dict if Tier-2 must not run, else None.

    Two guards, both cheap:
      1. circuit breaker — disabled after repeated failures / by config
      2. memory guard    — preemptively disable when free RAM is low
    """
    ok, reason = tier2_available()
    if not ok:
        return {"ok": False, "error": reason or "tier2_disabled",
                "detail": "Tier-2 GUI automation is disabled; Tier-1 "
                          "capabilities (open_app/open_url/lock/screenshot/"
                          "dashboard) remain fully available."}
    mem = memory_guard()
    if mem.get("action") == "tier2_disabled_low_memory":
        return {"ok": False, "error": "tier2_disabled_low_memory",
                "detail": f"Free RAM {mem['available_mb']}MB < "
                          f"{TIER2_MIN_FREE_MB}MB threshold — Tier-2 disabled "
                          f"to protect system stability."}
    return None


def _tier2_finish(result: dict, action: str) -> dict:
    """Feed a Tier-2 result into the circuit breaker and annotate it."""
    if result.get("ok"):
        tier2_record_success()
        return result
    err = result.get("error", "unknown")
    # Import/runtime failures count toward the circuit breaker
    if err in ("pyautogui_missing", "no_display", "gui_module_error"):
        tier2_record_failure(err)
    return result


def handle_gui_type(text: str) -> dict:
    """Type text into the focused window (Tier 2, needs pyautogui)."""
    gate = _tier2_gate()
    if gate:
        return gate
    try:
        gui = _load_gui_module()
    except Exception as e:
        return _tier2_finish({"ok": False, "error": "gui_module_error",
                              "detail": str(e)}, "gui_type")
    return _tier2_finish(gui.type_text(text), "gui_type")


def handle_gui_key(keys: str) -> dict:
    """Press a key or combo, e.g. 'enter' or 'ctrl+alt+l' (Tier 2)."""
    gate = _tier2_gate()
    if gate:
        return gate
    try:
        gui = _load_gui_module()
    except Exception as e:
        return _tier2_finish({"ok": False, "error": "gui_module_error",
                              "detail": str(e)}, "gui_key")
    if "+" in keys:
        result = gui.hotkey(*[k.strip() for k in keys.split("+") if k.strip()])
    else:
        result = gui.press_key(keys.strip())
    return _tier2_finish(result, "gui_key")


def handle_gui_click(args: str) -> dict:
    """Click at 'x,y' or at the current position if args == 'current' (Tier 2)."""
    # Validate input format first so arg errors are reported precisely
    if args.strip().lower() == "current":
        coords = None
    else:
        try:
            x_str, y_str = args.split(",", 1)
            coords = (int(x_str.strip()), int(y_str.strip()))
        except ValueError:
            return {"ok": False, "error": "invalid_args",
                    "detail": "gui_click args must be 'x,y' or 'current'"}
    gate = _tier2_gate()
    if gate:
        return gate
    try:
        gui = _load_gui_module()
    except Exception as e:
        return _tier2_finish({"ok": False, "error": "gui_module_error",
                              "detail": str(e)}, "gui_click")
    if coords is None:
        return _tier2_finish(gui.click(), "gui_click")
    return _tier2_finish(gui.click(coords[0], coords[1]), "gui_click")


def execute_action(action: str, args: str | None) -> dict:
    """Execute an allowlisted action."""
    cmd_config = BUILTIN_COMMANDS.get(action)
    if not cmd_config:
        return {"ok": False, "error": "unknown_action",
                "detail": f"Action '{action}' is not in the allowlist"}

    # Check if action requires args
    if cmd_config.get("requires_args") and not args:
        return {"ok": False, "error": "missing_args",
                "detail": f"Action '{action}' requires arguments"}

    # Check for handler (custom Python function)
    handler = cmd_config.get("handler")
    if handler:
        if handler == "status":
            return handle_status()
        elif handler == "screenshot":
            return handle_screenshot()
        elif handler == "script":
            return handle_script(args)
        elif handler == "wake":
            return handle_wake(args)
        elif handler == "open_app":
            return handle_open_app(args)
        elif handler == "open_url":
            return handle_open_url(args)
        elif handler == "dashboard":
            return handle_dashboard()
        elif handler == "gui_type":
            return handle_gui_type(args)
        elif handler == "gui_key":
            return handle_gui_key(args)
        elif handler == "gui_click":
            return handle_gui_click(args)

    # Subprocess-based command
    platform_key = PLATFORM
    cmd_template = cmd_config.get(platform_key)
    if not cmd_template:
        return {"ok": False, "error": "unsupported_platform",
                "detail": f"Action '{action}' has no command for {platform_key}"}

    # Substitute {arg} placeholder
    cmd_args = []
    for part in cmd_template:
        if "{arg}" in part:
            if not args:
                return {"ok": False, "error": "missing_args",
                        "detail": f"Action '{action}' requires args for template"}
            cmd_args.append(part.replace("{arg}", args))
        else:
            cmd_args.append(part)

    # Destructive action — add confirmation delay
    if cmd_config.get("destructive", False):
        logger.warning(f"Destructive action '{action}' — waiting {DESTRUCTIVE_CONFIRM_DELAY}s before execution")
        time.sleep(DESTRUCTIVE_CONFIRM_DELAY)

    logger.info(f"Executing: action={action}, cmd={cmd_args}")
    result = execute_subprocess(cmd_args)
    result["action"] = action
    result["platform"] = platform_key
    return result


# ════════════════════════════════════════════════════════════════
# WEB UI (login + credential generator)
# ════════════════════════════════════════════════════════════════

WEBUI_ENABLED = os.environ.get("MINA_WEBUI", "on").strip().lower() \
    not in ("off", "0", "false", "no")
WEBUI = None  # set in main() when enabled and modules import


def _webui_on_credentials(api_key: str, hmac_secret: str) -> None:
    """Hot-inject freshly generated credentials into the live daemon."""
    MinaHandler.api_key = api_key
    MinaHandler.hmac_secret = hmac_secret
    logger.info("Credentials rotated via web UI — new pair active "
                "(old keys rejected from now on)")


def _load_bootstrap_credentials() -> tuple[str, str] | None:
    """Load ~/.mina/credentials.env when env vars are not provided."""
    if not HAS_WEBUI_MODULES:
        return None
    creds = mina_auth.load_credentials()
    if creds:
        return creds["api_key"], creds["hmac_secret"]
    return None


# ════════════════════════════════════════════════════════════════
# HTTP REQUEST HANDLER
# ════════════════════════════════════════════════════════════════

class MinaHandler(BaseHTTPRequestHandler):
    """HTTP handler for receiving commands from Hermes."""

    # Config injected at runtime
    api_key: str = ""
    hmac_secret: str = ""

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Health check + web UI routes."""
        # Web UI first (login/dashboard/setup + "/" redirect)
        if WEBUI is not None:
            try:
                if WEBUI.route_get(self):
                    return
            except Exception:
                logger.error("Web UI GET error", exc_info=True)
        if self.path == "/health":
            self._send_json(200, {
                "ok": True,
                "service": "mina-local-daemon",
                "version": "1.3.0",
                "platform": PLATFORM,
                "hostname": platform.node(),
                "timestamp": int(time.time()),
                "tier2_enabled": TIER2_STATE["enabled"],
                "webui_enabled": WEBUI is not None,
            })
        elif self.path == "/":
            self._send_json(200, {"ok": True, "message": "Mina daemon running. POST /command"})
        else:
            self._send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        """Receive and execute a command (or handle a web UI form POST)."""
        # Web UI form endpoints first (/ui/login, /ui/setup, /ui/generate,
        # /ui/logout). Anything else falls through to /command handling.
        if WEBUI is not None and self.path.startswith("/ui/"):
            try:
                if WEBUI.route_post(self):
                    return
            except Exception:
                logger.error("Web UI POST error", exc_info=True)
        if self.path != "/command":
            self._send_json(404, {"ok": False, "error": "not_found"})
            return

        # ── Step 1: Verify Bearer token ──
        # Unconfigured daemon (no credentials yet) rejects ALL commands —
        # otherwise an empty api_key would match an empty bearer token.
        if not self.api_key or not self.hmac_secret:
            logger.warning("Command rejected: daemon has no credentials configured")
            self._send_json(503, {"ok": False, "error": "not_configured",
                                  "detail": "No credentials. Open the web UI "
                                            "(/ui/) to generate API & secret key."})
            return
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning("Missing Bearer token")
            self._send_json(401, {"ok": False, "error": "unauthorized", "detail": "Missing Bearer token"})
            return

        token = auth_header[7:]
        if not hmac.compare_digest(token, self.api_key):
            logger.warning("Invalid API key")
            self._send_json(401, {"ok": False, "error": "unauthorized", "detail": "Invalid API key"})
            return

        # ── Step 2: Read body ──
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0 or content_length > 65536:
            self._send_json(400, {"ok": False, "error": "invalid_body_size"})
            return

        body = self.rfile.read(content_length)

        # ── Step 3: Verify HMAC signature ──
        signature = self.headers.get("X-Mina-Signature", "")
        if not signature:
            self._send_json(401, {"ok": False, "error": "missing_signature"})
            return

        if not verify_hmac(body, signature, self.hmac_secret):
            logger.warning("HMAC verification failed")
            self._send_json(401, {"ok": False, "error": "invalid_signature"})
            return

        # ── Step 4: Parse JSON payload ──
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "invalid_json"})
            return

        action = payload.get("action", "")
        args = payload.get("args")
        timestamp = payload.get("timestamp", 0)
        nonce = payload.get("nonce", "")

        # ── Step 5: Replay protection ──
        if not check_replay(nonce, timestamp):
            logger.warning(f"Replay detected: nonce={nonce}, ts={timestamp}")
            self._send_json(401, {"ok": False, "error": "replay_detected",
                                  "detail": "Nonce already seen or timestamp out of window"})
            return

        # ── Step 6: Rate limiting ──
        if not check_rate_limit(action):
            logger.warning(f"Rate limited: action={action}")
            self._send_json(429, {"ok": False, "error": "rate_limited",
                                  "detail": f"Too many '{action}' requests. Limit: {RATE_LIMITS.get(action, 10)}/hour"})
            return

        # ── Step 7: Execute action ──
        logger.info(f"Command received: action={action}, args={args}")
        try:
            result = execute_action(action, args)
            if result.get("ok"):
                status_code = 200
            else:
                # Client errors (4xx) vs server errors (5xx)
                client_errors = {
                    "unknown_action", "missing_args", "invalid_script_name",
                    "script_not_found", "path_traversal_blocked",
                    "unsupported_extension", "unsupported_platform",
                }
                if result.get("error") in client_errors:
                    status_code = 400
                else:
                    status_code = 500
            self._send_json(status_code, result)
            logger.info(f"Action '{action}' result: ok={result.get('ok')}")
        except Exception as e:
            logger.error(f"Action execution error: {e}", exc_info=True)
            self._send_json(500, {"ok": False, "error": "internal_error", "detail": str(e)})

    def log_message(self, format, *args):
        """Suppress default HTTP logging — we use our own logger."""
        pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server for concurrent requests."""
    daemon_threads = True


# ════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Mina Local Daemon")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MINA_DAEMON_PORT", DEFAULT_PORT)))
    parser.add_argument("--api-key", type=str, default=os.environ.get("MINA_API_KEY", ""))
    parser.add_argument("--hmac-secret", type=str, default=os.environ.get("MINA_HMAC_SECRET", ""))
    parser.add_argument("--host", type=str, default="127.0.0.1")
    args_cli = parser.parse_args()

    # ── Credential resolution order ──────────────────────────────
    # 1. CLI flags  2. env vars  3. ~/.mina/credentials.env (web UI)
    # If none exist and the web UI is enabled, start anyway in "setup
    # mode" so the user can create the account + generate credentials
    # from the browser. Without the web UI, behave as before (exit).
    api_key = args_cli.api_key
    hmac_secret = args_cli.hmac_secret
    creds_source = "cli/env" if (api_key and hmac_secret) else None
    if not (api_key and hmac_secret):
        bootstrap = _load_bootstrap_credentials()
        if bootstrap:
            api_key, hmac_secret = bootstrap
            creds_source = "credentials.env"

    setup_mode = not (api_key and hmac_secret)
    if setup_mode and not (WEBUI_ENABLED and HAS_WEBUI_MODULES):
        print("=" * 60)
        print("ERROR: MINA_API_KEY and MINA_HMAC_SECRET required.")
        print()
        print("Generate secrets:")
        print('  python -c "import secrets; print(\'mina_sk_\' + secrets.token_urlsafe(32))"')
        print('  python -c "import secrets; print(secrets.token_hex(32))"')
        print()
        print("Set as env vars or pass via --api-key --hmac-secret")
        print("=" * 60)
        sys.exit(1)

    MinaHandler.api_key = api_key
    MinaHandler.hmac_secret = hmac_secret

    # ── Web UI bootstrap ─────────────────────────────────────────
    global WEBUI
    setup_token = ""
    if WEBUI_ENABLED and HAS_WEBUI_MODULES:
        import secrets as _secrets
        setup_token = _secrets.token_urlsafe(16)
        WEBUI = mina_webui.WebUI(setup_token=setup_token,
                                 on_credentials_generated=_webui_on_credentials)

    server = ThreadingHTTPServer((args_cli.host, args_cli.port), MinaHandler)

    logger.info("=" * 60)
    logger.info("Mina Local Daemon v1.3.0")
    logger.info(f"  Platform: {PLATFORM} ({platform.node()})")
    logger.info(f"  Listen:   {args_cli.host}:{args_cli.port}")
    logger.info(f"  Scripts:  {SCRIPTS_DIR}")
    logger.info(f"  Log:      {LOG_FILE}")
    logger.info(f"  psutil:   {'available' if HAS_PSUTIL else 'NOT installed (status limited)'}")
    logger.info(f"  Profile:  status_cpu_sample={STATUS_CPU_SAMPLE_INTERVAL}s, "
                f"cmd_timeout={CMD_TIMEOUT_SECONDS}s, "
                f"dashboard_refresh={DASHBOARD_REFRESH_SECONDS}s")
    if TIER2_STATE["enabled"]:
        logger.info(f"  Tier-2:   enabled (min_free_ram={TIER2_MIN_FREE_MB}MB, "
                    f"circuit_breaker={TIER2_MAX_FAILURES} failures)")
    else:
        logger.info(f"  Tier-2:   DISABLED ({TIER2_STATE['reason']}) — "
                    f"Tier-1 capabilities remain active")
    if WEBUI is not None:
        logger.info(f"  Web UI:   http://{args_cli.host}:{args_cli.port}/ui/ "
                    f"(login + credential generator)")
    if setup_mode:
        logger.warning("=" * 60)
        logger.warning("  SETUP MODE — no credentials yet.")
        logger.warning(f"  Open http://127.0.0.1:{args_cli.port}/ui/setup")
        logger.warning(f"  SETUP TOKEN (one-time): {setup_token}")
        logger.warning("  /command endpoint is locked until credentials "
                       "are generated via the web UI.")
        logger.warning("=" * 60)
    elif creds_source:
        logger.info(f"  Creds:    loaded from {creds_source}")
    mem = memory_guard()
    if mem.get("action") != "none":
        logger.warning(f"  Memory:   {mem}")
    logger.info("=" * 60)

    # Graceful shutdown
    def shutdown(signum, frame):
        logger.info(f"Signal {signum} received — shutting down")
        # server.shutdown() must NOT be called on the serve_forever() thread:
        # it blocks on an event that only gets set after serve_forever()
        # returns — from a signal handler that is a guaranteed deadlock.
        # Delegate to a short-lived thread, then unwind via SystemExit.
        threading.Thread(target=server.shutdown, daemon=True).start()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Daemon ready. Waiting for commands...")
    try:
        server.serve_forever()
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        # Auto-restart logic
        logger.info("Attempting restart in 5s...")
        time.sleep(5)
        os.execv(sys.executable, [sys.executable] + sys.argv)


if __name__ == "__main__":
    main()
