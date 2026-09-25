#!/usr/bin/env python3
"""
Mina GUI Automation — screen & GUI control helpers.

Two tiers:
  1. Fallback tier (no extra deps): open apps / URLs via platform-native
     launchers (xdg-open, open, cmd start). Used by the daemon's
     `open_app` and `dashboard` actions.
  2. Rich tier (optional, requires pyautogui): type text, press keys,
     mouse control. Import is lazy so the daemon runs fine without it.

Security: this module NEVER builds shell strings. Every launcher returns
an argv list for subprocess.run(shell=False). App names are resolved by
the caller against an allowlist (commands.yaml -> apps:).

Capability probe:
    python3 gui_automation.py --check
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
from pathlib import Path


def get_platform() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


PLATFORM = get_platform()


# ── Capability detection ─────────────────────────────────────────

def detect_backends() -> dict:
    """Report which GUI backends are available on this machine."""
    info = {
        "platform": PLATFORM,
        "display": os.environ.get("DISPLAY")
        or os.environ.get("WAYLAND_DISPLAY") or None,
        "pyautogui": False,
        "tools": {},
    }
    try:
        import pyautogui  # noqa: F401
        info["pyautogui"] = True
    except ImportError:
        pass

    tools = {
        "linux": ["xdg-open", "xdotool", "wmctrl", "scrot",
                  "gnome-screenshot", "loginctl"],
        "macos": ["open", "osascript", "screencapture", "pmset"],
        "windows": ["powershell"],
    }
    for tool in tools.get(PLATFORM, []):
        info["tools"][tool] = shutil.which(tool) is not None
    return info


def display_available() -> bool:
    """True if a graphical session is reachable (always True off Linux)."""
    if PLATFORM != "linux":
        return True
    return bool(os.environ.get("DISPLAY")
                or os.environ.get("WAYLAND_DISPLAY"))


# ── Tier 1: launcher argv builders (no deps) ─────────────────────

def open_url_cmd(url: str) -> list[str] | None:
    """Build the argv to open a URL in the default browser."""
    if not url.startswith(("http://", "https://", "file://")):
        return None
    if PLATFORM == "linux":
        return ["xdg-open", url]
    if PLATFORM == "macos":
        return ["open", url]
    return ["cmd", "/c", "start", "", url]


def open_app_cmd(app_spec: dict) -> list[str] | None:
    """Resolve a platform command array from an allowlist app spec.

    app_spec example:
        {"linux": ["code"], "macos": ["open", "-a", "Visual Studio Code"],
         "windows": ["cmd", "/c", "start", "", "code"]}
    """
    cmd = app_spec.get(PLATFORM)
    if not cmd:
        return None
    # Expand ~ for file-ish args (shell=False means no shell expansion)
    return [os.path.expanduser(p) if isinstance(p, str) and p.startswith("~")
            else p for p in cmd]


# ── Tier 2: pyautogui-backed actions (optional) ──────────────────

def _require_pyautogui():
    if not display_available():
        return {"ok": False, "error": "no_display",
                "detail": "No DISPLAY/WAYLAND_DISPLAY — GUI actions need "
                          "a graphical session (and daemon started from it)."}
    try:
        import pyautogui
        pyautogui.FAILSAFE = True  # slam mouse to a corner to abort
        return pyautogui
    except ImportError:
        return {"ok": False, "error": "pyautogui_missing",
                "detail": "pip install pyautogui (optional Tier-2 backend)"}


def type_text(text: str, interval: float = 0.02) -> dict:
    """Type text into the focused window."""
    pg = _require_pyautogui()
    if isinstance(pg, dict):
        return pg
    pg.typewrite(text, interval=interval)
    return {"ok": True, "typed": len(text)}


def press_key(key: str) -> dict:
    """Press a single key (e.g. 'enter', 'f11', 'esc')."""
    pg = _require_pyautogui()
    if isinstance(pg, dict):
        return pg
    pg.press(key)
    return {"ok": True, "key": key}


def hotkey(*keys: str) -> dict:
    """Press a key combo (e.g. hotkey('ctrl', 'alt', 'l'))."""
    pg = _require_pyautogui()
    if isinstance(pg, dict):
        return pg
    pg.hotkey(*keys)
    return {"ok": True, "keys": list(keys)}


def move_mouse(x: int, y: int) -> dict:
    pg = _require_pyautogui()
    if isinstance(pg, dict):
        return pg
    pg.moveTo(x, y)
    return {"ok": True, "x": x, "y": y}


def click(x: int | None = None, y: int | None = None) -> dict:
    pg = _require_pyautogui()
    if isinstance(pg, dict):
        return pg
    if x is not None and y is not None:
        pg.click(x, y)
    else:
        pg.click()
    return {"ok": True, "x": x, "y": y}


def screenshot(path: str | None = None) -> dict:
    """Screenshot via pyautogui (Tier 2) — daemon has its own fallbacks."""
    pg = _require_pyautogui()
    if isinstance(pg, dict):
        return pg
    out = path or str(Path.home() / ".mina" / "screenshot.png")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    pg.screenshot(out)
    return {"ok": True, "screenshot": out}


def main() -> None:
    parser = argparse.ArgumentParser(description="Mina GUI automation probe")
    parser.add_argument("--check", action="store_true",
                        help="Print backend capability report")
    args = parser.parse_args()
    if args.check:
        import json
        print(json.dumps(detect_backends(), indent=2))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
