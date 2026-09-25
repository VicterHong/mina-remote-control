"""
Test suite for MINA extended capabilities:
  - Wake-on-LAN (wol.py + daemon handler)
  - GUI automation (gui_automation.py + daemon handlers)
  - Dashboard generation (dashboard.py)
  - New natural-language patterns in send_command.py

Run:
    cd the repository root
    python3 -m pytest tests/test_mina_extended.py -v
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


# ════════════════════════════════════════════════════════════════
# WAKE-ON-LAN — wol.py unit tests
# ════════════════════════════════════════════════════════════════

class TestWolMagicPacket:
    def test_packet_is_102_bytes(self):
        import wol
        p = wol.build_magic_packet("AA:BB:CC:DD:EE:FF")
        assert len(p) == 102

    def test_packet_header_is_six_ff(self):
        import wol
        p = wol.build_magic_packet("AA:BB:CC:DD:EE:FF")
        assert p[:6] == b"\xff" * 6

    def test_packet_repeats_mac_16_times(self):
        import wol
        p = wol.build_magic_packet("AA:BB:CC:DD:EE:FF")
        mac = bytes.fromhex("aabbccddeeff")
        assert p[6:] == mac * 16

    def test_hyphenated_mac_accepted(self):
        import wol
        p = wol.build_magic_packet("AA-BB-CC-DD-EE-FF")
        assert p[6:12].hex() == "aabbccddeeff"

    def test_lowercase_mac_accepted(self):
        import wol
        p = wol.build_magic_packet("aa:bb:cc:dd:ee:ff")
        assert len(p) == 102

    def test_invalid_mac_rejected(self):
        import wol
        with pytest.raises(ValueError):
            wol.build_magic_packet("ZZ:BB:CC:DD:EE:FF")

    def test_short_mac_rejected(self):
        import wol
        with pytest.raises(ValueError):
            wol.build_magic_packet("AA:BB:CC")

    def test_empty_mac_rejected(self):
        import wol
        with pytest.raises(ValueError):
            wol.build_magic_packet("")


class TestWolSend:
    def test_send_to_localhost(self):
        import wol
        r = wol.send_magic_packet("AA:BB:CC:DD:EE:FF",
                                  broadcast="127.0.0.1", port=9)
        assert r["ok"] is True
        assert r["mac"] == "aa:bb:cc:dd:ee:ff"
        assert r["bytes"] == 102

    def test_send_invalid_mac_returns_error(self):
        import wol
        r = wol.send_magic_packet("not-a-mac")
        assert r["ok"] is False
        assert r["error"] == "invalid_mac"

    def test_wake_unknown_device(self):
        import wol
        r = wol.wake_device("definitely-not-registered-xyz")
        assert r["ok"] is False
        assert r["error"] == "unknown_device"

    def test_normalize_mac(self):
        import wol
        assert wol.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


# ════════════════════════════════════════════════════════════════
# GUI AUTOMATION — gui_automation.py unit tests
# ════════════════════════════════════════════════════════════════

class TestGuiLaunchers:
    def test_open_url_cmd_http(self):
        import gui_automation as gui
        cmd = gui.open_url_cmd("http://example.com")
        assert cmd is not None
        assert "http://example.com" in cmd

    def test_open_url_cmd_https(self):
        import gui_automation as gui
        cmd = gui.open_url_cmd("https://example.com")
        assert cmd is not None

    def test_open_url_cmd_file(self):
        import gui_automation as gui
        cmd = gui.open_url_cmd("file:///tmp/x.html")
        assert cmd is not None

    def test_open_url_rejects_javascript_scheme(self):
        import gui_automation as gui
        assert gui.open_url_cmd("javascript:alert(1)") is None

    def test_open_url_rejects_shell_injection(self):
        import gui_automation as gui
        assert gui.open_url_cmd("http://x; rm -rf /") is not None  # stays argv
        # The important part: it returns an argv list, never a shell string
        cmd = gui.open_url_cmd("http://x; rm -rf /")
        assert isinstance(cmd, list)

    def test_open_app_cmd_linux(self):
        import gui_automation as gui
        spec = {"linux": ["code"], "macos": ["open", "-a", "Code"]}
        cmd = gui.open_app_cmd(spec)
        if gui.PLATFORM == "linux":
            assert cmd == ["code"]
        elif gui.PLATFORM == "macos":
            assert cmd == ["open", "-a", "Code"]

    def test_open_app_cmd_expands_tilde(self):
        import gui_automation as gui
        spec = {gui.PLATFORM: ["xdg-open", "~/somefile"]}
        cmd = gui.open_app_cmd(spec)
        assert cmd is not None
        assert not cmd[-1].startswith("~")

    def test_open_app_cmd_missing_platform(self):
        import gui_automation as gui
        assert gui.open_app_cmd({"amigaos": ["x"]}) is None

    def test_detect_backends_shape(self):
        import gui_automation as gui
        info = gui.detect_backends()
        assert "platform" in info
        assert "tools" in info
        assert isinstance(info["pyautogui"], bool)


class TestGuiTier2WithoutPyautogui:
    """Tier-2 actions must degrade gracefully, never crash."""

    def test_type_text_no_pyautogui(self):
        import gui_automation as gui
        with patch.object(gui, "_require_pyautogui",
                          return_value={"ok": False,
                                        "error": "pyautogui_missing"}):
            r = gui.type_text("hello")
            assert r["ok"] is False

    def test_press_key_no_pyautogui(self):
        import gui_automation as gui
        with patch.object(gui, "_require_pyautogui",
                          return_value={"ok": False,
                                        "error": "pyautogui_missing"}):
            r = gui.press_key("enter")
            assert r["ok"] is False

    def test_no_display_returns_error(self):
        import gui_automation as gui
        with patch.object(gui, "display_available", return_value=False):
            r = gui._require_pyautogui()
            assert r["ok"] is False
            assert r["error"] == "no_display"


# ════════════════════════════════════════════════════════════════
# DAEMON — new handlers
# ════════════════════════════════════════════════════════════════

class TestDaemonWakeHandler:
    def test_wake_unknown_device(self):
        import mina_daemon as d
        r = d.handle_wake("no-such-device-xyz")
        assert r["ok"] is False
        assert r["error"] == "unknown_device"

    def test_wake_raw_mac_sends(self):
        import mina_daemon as d
        r = d.handle_wake("AA:BB:CC:DD:EE:FF")
        assert r["ok"] is True
        assert r["bytes"] == 102


class TestDaemonGuiHandlers:
    def test_open_app_unknown(self):
        import mina_daemon as d
        r = d.handle_open_app("notanaop")
        assert r["ok"] is False
        assert r["error"] == "unknown_app"

    def test_open_app_invalid_name(self):
        import mina_daemon as d
        r = d.handle_open_app("bad name; rm -rf /")
        assert r["ok"] is False
        assert r["error"] == "invalid_app_name"

    def test_open_url_invalid_scheme(self):
        import mina_daemon as d
        r = d.handle_open_url("gopher://x")
        assert r["ok"] is False
        assert r["error"] == "invalid_url"

    def test_gui_click_invalid_args(self):
        import mina_daemon as d
        r = d.handle_gui_click("not-coords")
        assert r["ok"] is False
        assert r["error"] == "invalid_args"

    def test_dashboard_handler_exists(self):
        import mina_daemon as d
        assert callable(d.handle_dashboard)

    def test_wake_registered_in_actions(self):
        import mina_daemon as d
        for action in ("wake", "open_app", "open_url", "dashboard",
                       "gui_type", "gui_key", "gui_click"):
            assert action in d.BUILTIN_COMMANDS, action

    def test_rate_limits_cover_new_actions(self):
        import mina_daemon as d
        for action in ("wake", "open_app", "open_url", "dashboard",
                       "gui_type", "gui_key", "gui_click"):
            assert action in d.RATE_LIMITS, action


# ════════════════════════════════════════════════════════════════
# DASHBOARD — generation test
# ════════════════════════════════════════════════════════════════

class TestDashboard:
    def test_render_html_contains_sections(self, tmp_path):
        import dashboard
        m = {"hostname": "testhost", "platform": "linux",
             "generated_at": "2024-01-01 00:00:00",
             "cpu_percent": 42.0, "mem_percent": 55.0,
             "mem_used_gb": 8.0, "mem_total_gb": 16.0,
             "disk_percent": 30.0, "disk_used_gb": 100.0,
             "disk_total_gb": 500.0, "uptime_h": 72.0}
        containers = [{"name": "web", "status": "Up 2 hours",
                       "image": "nginx:latest"}]
        html = dashboard.render_html(m, containers, ["log line"], None)
        assert "testhost" in html
        assert "CPU" in html
        assert "Memory" in html
        assert "Disk" in html
        assert "web" in html
        assert "log line" in html

    def test_render_html_escapes_injection(self):
        import dashboard
        m = {"hostname": "<script>alert(1)</script>",
             "platform": "linux", "generated_at": "now"}
        html = dashboard.render_html(m, [], [], None)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_collect_metrics_shape(self):
        import dashboard
        m = dashboard.collect_metrics()
        assert "hostname" in m
        assert "generated_at" in m


# ════════════════════════════════════════════════════════════════
# SENDER — new NL patterns
# ════════════════════════════════════════════════════════════════

class TestNewNlPatterns:
    def _parse(self, text):
        import send_command as sc
        return sc.parse_natural_language(text)

    # ── Wake-on-LAN ──
    def test_wake_bangunkan(self):
        assert self._parse("bangunkan nas") == ("wake", "nas")

    def test_wake_english(self):
        assert self._parse("wake up pc2") == ("wake", "pc2")

    def test_wake_mac_address(self):
        assert self._parse("wake AA:BB:CC:DD:EE:FF") == ("wake", "AA:BB:CC:DD:EE:FF")

    def test_wake_no_arg(self):
        action, _ = self._parse("wake")
        assert action.startswith("error") or action == "wake"

    # ── open_app ──
    def test_open_app_indonesian(self):
        assert self._parse("buka aplikasi browser") == ("open_app", "browser")

    def test_open_app_english(self):
        assert self._parse("open app terminal") == ("open_app", "terminal")

    # ── open_url ──
    def test_open_url_indonesian(self):
        assert self._parse("buka url https://example.com") == \
            ("open_url", "https://example.com")

    def test_open_url_keeps_case(self):
        action, arg = self._parse("open url https://Example.COM/Path")
        assert action == "open_url"
        assert arg == "https://Example.COM/Path"

    # ── dashboard ──
    def test_dashboard_indonesian(self):
        assert self._parse("tampilkan dashboard") == ("dashboard", None)

    def test_dashboard_english(self):
        assert self._parse("show dashboard") == ("dashboard", None)

    def test_monitoring_keyword(self):
        assert self._parse("monitoring") == ("dashboard", None)

    # ── gui_type ──
    def test_gui_type_indonesian(self):
        action, arg = self._parse("ketik halo dunia")
        assert action == "gui_type"
        assert arg == "halo dunia"

    def test_gui_type_preserves_case(self):
        action, arg = self._parse("type Hello World")
        assert action == "gui_type"
        assert arg == "Hello World"

    # ── gui_key ──
    def test_gui_key_combo(self):
        action, arg = self._parse("tekan tombol ctrl+alt+l")
        assert action == "gui_key"
        assert arg == "ctrl+alt+l"

    def test_gui_key_single(self):
        assert self._parse("press key enter") == ("gui_key", "enter")

    # ── gui_click ──
    def test_gui_click_coords(self):
        assert self._parse("klik 100,200") == ("gui_click", "100,200")

    def test_gui_click_current(self):
        assert self._parse("click") == ("gui_click", "current")

    # ── regression: old patterns still work ──
    def test_shutdown_still_works(self):
        assert self._parse("matikan laptop") == ("shutdown", None)

    def test_status_still_works(self):
        assert self._parse("status") == ("status", None)

    def test_volume_still_works(self):
        assert self._parse("volume 50") == ("volume", "50")

    def test_unknown_still_unknown(self):
        assert self._parse("xyzzy foobar") == ("unknown", None)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
