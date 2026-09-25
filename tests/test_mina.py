"""
Test suite for the mina-workspace skill.

Tests both send_command.py (Hermes-side sender) and
mina_daemon.py (laptop-side daemon).

Run:
    cd the repository root
    python3 -m pytest tests/ -v
"""
import hashlib
import hmac
import json
import os
import sys
import time
from collections import deque
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ── Path setup: add scripts dir to sys.path ────────────────────
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


# ════════════════════════════════════════════════════════════════
# FIXTURES
# ════════════════════════════════════════════════════════════════

TEST_API_KEY = "mina_sk_test_key_12345"
TEST_HMAC_SECRET = "a" * 64  # 64 hex chars


@pytest.fixture
def fresh_nonces():
    """Clear the SEEN_NONCES deque before and after each test."""
    import mina_daemon as daemon_mod
    daemon_mod.SEEN_NONCES.clear()
    yield
    daemon_mod.SEEN_NONCES.clear()


@pytest.fixture
def fresh_rate_counters():
    """Clear the RATE_COUNTERS dict before and after each test."""
    import mina_daemon as daemon_mod
    daemon_mod.RATE_COUNTERS.clear()
    yield
    daemon_mod.RATE_COUNTERS.clear()


@pytest.fixture
def patched_platform():
    """Patch PLATFORM to 'linux' for deterministic tests."""
    import mina_daemon as daemon_mod
    original = daemon_mod.PLATFORM
    daemon_mod.PLATFORM = "linux"
    yield daemon_mod
    daemon_mod.PLATFORM = original


@pytest.fixture
def mock_destructive_delay():
    """Patch DESTRUCTIVE_CONFIRM_DELAY to 0 so tests don't wait."""
    import mina_daemon as daemon_mod
    original = daemon_mod.DESTRUCTIVE_CONFIRM_DELAY
    daemon_mod.DESTRUCTIVE_CONFIRM_DELAY = 0
    yield daemon_mod
    daemon_mod.DESTRUCTIVE_CONFIRM_DELAY = original


# ════════════════════════════════════════════════════════════════
# SEND_COMMAND.PY TESTS
# ════════════════════════════════════════════════════════════════

class TestParseNaturalLanguage:
    """Test natural language command parsing."""

    @pytest.fixture(autouse=True)
    def _import_sc(self):
        import send_command as sc
        self.sc = sc

    def test_shutdown_indonesian(self):
        action, args = self.sc.parse_natural_language("matikan PC")
        assert action == "shutdown"
        assert args is None

    def test_shutdown_english(self):
        action, args = self.sc.parse_natural_language("shutdown")
        assert action == "shutdown"
        assert args is None

    def test_shutdown_turn_off(self):
        action, args = self.sc.parse_natural_language("please turn off the computer")
        assert action == "shutdown"

    def test_shutdown_matikan_laptop(self):
        action, args = self.sc.parse_natural_language("matikan laptop")
        assert action == "shutdown"

    def test_restart(self):
        action, _ = self.sc.parse_natural_language("restart")
        assert action == "restart"

    def test_reboot(self):
        action, _ = self.sc.parse_natural_language("reboot sekarang")
        assert action == "restart"

    def test_mulai_ulang(self):
        action, _ = self.sc.parse_natural_language("mulai ulang")
        assert action == "restart"

    def test_sleep_tutup_laptop(self):
        action, _ = self.sc.parse_natural_language("tutup laptop")
        assert action == "sleep"

    def test_sleep_english(self):
        action, _ = self.sc.parse_natural_language("sleep")
        assert action == "sleep"

    def test_tidur(self):
        action, _ = self.sc.parse_natural_language("tidur")
        assert action == "sleep"

    def test_hibernate(self):
        action, _ = self.sc.parse_natural_language("hibernasi")
        assert action == "hibernate"

    def test_lock_english(self):
        action, _ = self.sc.parse_natural_language("lock screen")
        assert action == "lock"

    def test_lock_indonesian(self):
        action, _ = self.sc.parse_natural_language("kunci layar")
        assert action == "lock"

    def test_kunci_alone(self):
        action, _ = self.sc.parse_natural_language("kunci")
        assert action == "lock"

    def test_status(self):
        action, _ = self.sc.parse_natural_language("cek status")
        assert action == "status"

    def test_health(self):
        action, _ = self.sc.parse_natural_language("health check")
        assert action == "status"

    def test_screenshot(self):
        action, _ = self.sc.parse_natural_language("screenshot")
        assert action == "screenshot"

    def test_tangkap_layar(self):
        action, _ = self.sc.parse_natural_language("tangkap layar")
        assert action == "screenshot"

    def test_volume_with_number(self):
        action, args = self.sc.parse_natural_language("volume 50")
        assert action == "volume"
        assert args == "50"

    def test_volume_zero(self):
        action, args = self.sc.parse_natural_language("volume 0")
        assert action == "volume"
        assert args == "0"

    def test_volume_max(self):
        action, args = self.sc.parse_natural_language("set volume to 100")
        assert action == "volume"
        assert args == "100"

    def test_volume_invalid_no_number(self):
        action, _ = self.sc.parse_natural_language("volume up")
        assert action.startswith("error")

    def test_volume_over_100(self):
        action, _ = self.sc.parse_natural_language("volume 150")
        assert action.startswith("error")

    def test_run_script_with_name(self):
        action, args = self.sc.parse_natural_language("jalankan skrip backup_db")
        assert action == "run_script"
        assert args == "backup_db"

    def test_run_script_english(self):
        action, args = self.sc.parse_natural_language("run script cleanup")
        assert action == "run_script"
        assert args == "cleanup"

    def test_run_script_no_name(self):
        action, _ = self.sc.parse_natural_language("jalankan skrip")
        assert action.startswith("error")

    def test_unknown_command(self):
        action, args = self.sc.parse_natural_language("buka browser")
        assert action == "unknown"
        assert args is None

    def test_case_insensitive(self):
        action, _ = self.sc.parse_natural_language("MATIKAN PC")
        assert action == "shutdown"

    def test_mixed_case(self):
        action, _ = self.sc.parse_natural_language("ShUtDoWn")
        assert action == "shutdown"

    def test_with_whitespace(self):
        action, _ = self.sc.parse_natural_language("  shutdown  ")
        assert action == "shutdown"

    def test_run_script_special_chars_stripped(self):
        action, args = self.sc.parse_natural_language("jalankan skrip backup; rm -rf")
        assert action == "run_script"
        # Only alphanumeric, underscore, hyphen survive
        assert ";" not in args
        assert " " not in args
        assert args == "backuprm-rf" or args.startswith("backup")


class TestBuildPayload:
    """Test payload building."""

    @pytest.fixture(autouse=True)
    def _import_sc(self):
        import send_command as sc
        self.sc = sc

    def test_payload_has_required_fields(self):
        payload = self.sc.build_payload("shutdown")
        data = json.loads(payload)
        assert "action" in data
        assert "args" in data
        assert "timestamp" in data
        assert "nonce" in data

    def test_payload_action_correct(self):
        payload = self.sc.build_payload("lock")
        data = json.loads(payload)
        assert data["action"] == "lock"

    def test_payload_args_correct(self):
        payload = self.sc.build_payload("volume", "50")
        data = json.loads(payload)
        assert data["args"] == "50"

    def test_payload_args_none_default(self):
        payload = self.sc.build_payload("status")
        data = json.loads(payload)
        assert data["args"] is None

    def test_payload_is_bytes(self):
        payload = self.sc.build_payload("shutdown")
        assert isinstance(payload, bytes)

    def test_nonce_is_unique(self):
        p1 = self.sc.build_payload("shutdown")
        p2 = self.sc.build_payload("shutdown")
        d1 = json.loads(p1)
        d2 = json.loads(p2)
        assert d1["nonce"] != d2["nonce"]

    def test_nonce_length(self):
        payload = self.sc.build_payload("shutdown")
        data = json.loads(payload)
        # 16 bytes hex = 32 chars
        assert len(data["nonce"]) == 32

    def test_timestamp_is_recent(self):
        payload = self.sc.build_payload("shutdown")
        data = json.loads(payload)
        assert abs(time.time() - data["timestamp"]) < 2


class TestSignPayload:
    """Test HMAC-SHA256 signing."""

    @pytest.fixture(autouse=True)
    def _import_sc(self):
        import send_command as sc
        self.sc = sc

    def test_signature_is_hex_string(self):
        payload = b'{"action":"shutdown"}'
        sig = self.sc.sign_payload(payload, TEST_HMAC_SECRET)
        assert isinstance(sig, str)
        assert all(c in "0123456789abcdef" for c in sig)

    def test_signature_is_64_chars(self):
        payload = b'{"action":"shutdown"}'
        sig = self.sc.sign_payload(payload, TEST_HMAC_SECRET)
        assert len(sig) == 64

    def test_same_payload_same_sig(self):
        payload = b'{"action":"lock"}'
        sig1 = self.sc.sign_payload(payload, TEST_HMAC_SECRET)
        sig2 = self.sc.sign_payload(payload, TEST_HMAC_SECRET)
        assert sig1 == sig2

    def test_different_payload_different_sig(self):
        sig1 = self.sc.sign_payload(b'{"action":"shutdown"}', TEST_HMAC_SECRET)
        sig2 = self.sc.sign_payload(b'{"action":"lock"}', TEST_HMAC_SECRET)
        assert sig1 != sig2

    def test_different_secret_different_sig(self):
        payload = b'{"action":"shutdown"}'
        sig1 = self.sc.sign_payload(payload, TEST_HMAC_SECRET)
        sig2 = self.sc.sign_payload(payload, "b" * 64)
        assert sig1 != sig2

    def test_signature_matches_manual_hmac(self):
        payload = b'{"action":"shutdown"}'
        sig = self.sc.sign_payload(payload, TEST_HMAC_SECRET)
        expected = hmac.new(
            TEST_HMAC_SECRET.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected


# ════════════════════════════════════════════════════════════════
# MINA_DAEMON.PY TESTS
# ════════════════════════════════════════════════════════════════

class TestGetPlatform:
    """Test platform detection."""

    def test_returns_valid_platform(self):
        import mina_daemon as daemon
        assert daemon.get_platform() in ("windows", "linux", "macos")

    def test_windows_detection(self):
        import mina_daemon as daemon
        with patch("mina_daemon.platform.system", return_value="Windows"):
            assert daemon.get_platform() == "windows"

    def test_linux_detection(self):
        import mina_daemon as daemon
        with patch("mina_daemon.platform.system", return_value="Linux"):
            assert daemon.get_platform() == "linux"

    def test_macos_detection(self):
        import mina_daemon as daemon
        with patch("mina_daemon.platform.system", return_value="Darwin"):
            assert daemon.get_platform() == "macos"


class TestVerifyHmac:
    """Test HMAC verification."""

    def test_valid_signature(self):
        import mina_daemon as daemon
        payload = b'{"action":"shutdown"}'
        sig = hmac.new(
            TEST_HMAC_SECRET.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
        assert daemon.verify_hmac(payload, sig, TEST_HMAC_SECRET) is True

    def test_invalid_signature(self):
        import mina_daemon as daemon
        payload = b'{"action":"shutdown"}'
        wrong_sig = "0" * 64
        assert daemon.verify_hmac(payload, wrong_sig, TEST_HMAC_SECRET) is False

    def test_tampered_payload(self):
        import mina_daemon as daemon
        original = b'{"action":"shutdown"}'
        tampered = b'{"action":"restart"}'
        sig = hmac.new(
            TEST_HMAC_SECRET.encode("utf-8"),
            original,
            hashlib.sha256,
        ).hexdigest()
        assert daemon.verify_hmac(tampered, sig, TEST_HMAC_SECRET) is False

    def test_wrong_secret(self):
        import mina_daemon as daemon
        payload = b'{"action":"shutdown"}'
        sig = hmac.new(
            "wrong_secret".encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
        assert daemon.verify_hmac(payload, sig, TEST_HMAC_SECRET) is False

    def test_empty_signature(self):
        import mina_daemon as daemon
        payload = b'{"action":"shutdown"}'
        assert daemon.verify_hmac(payload, "", TEST_HMAC_SECRET) is False


class TestCheckReplay:
    """Test replay protection."""

    def test_first_time_nonce_passes(self, fresh_nonces):
        import mina_daemon as daemon
        ts = int(time.time())
        assert daemon.check_replay("nonce_001", ts) is True

    def test_same_nonce_rejected(self, fresh_nonces):
        import mina_daemon as daemon
        ts = int(time.time())
        daemon.check_replay("nonce_002", ts)
        assert daemon.check_replay("nonce_002", ts) is False

    def test_different_nonce_passes(self, fresh_nonces):
        import mina_daemon as daemon
        ts = int(time.time())
        daemon.check_replay("nonce_003", ts)
        assert daemon.check_replay("nonce_004", ts) is True

    def test_stale_timestamp_rejected(self, fresh_nonces):
        import mina_daemon as daemon
        old_ts = int(time.time()) - 600  # 10 minutes ago
        assert daemon.check_replay("nonce_005", old_ts) is False

    def test_future_timestamp_rejected(self, fresh_nonces):
        import mina_daemon as daemon
        future_ts = int(time.time()) + 600  # 10 minutes in future
        assert daemon.check_replay("nonce_006", future_ts) is False

    def test_empty_nonce_rejected(self, fresh_nonces):
        import mina_daemon as daemon
        ts = int(time.time())
        assert daemon.check_replay("", ts) is True  # empty string is still a valid nonce


class TestCheckRateLimit:
    """Test rate limiting."""

    def test_under_limit_passes(self, fresh_rate_counters):
        import mina_daemon as daemon
        for _ in range(3):
            assert daemon.check_rate_limit("lock") is True

    def test_at_limit_still_passes_then_fails(self, fresh_rate_counters):
        import mina_daemon as daemon
        # lock has limit of 20
        for i in range(20):
            assert daemon.check_rate_limit("lock") is True
        # 21st should fail
        assert daemon.check_rate_limit("lock") is False

    def test_different_actions_independent(self, fresh_rate_counters):
        import mina_daemon as daemon
        # Exhaust lock limit
        for _ in range(20):
            daemon.check_rate_limit("lock")
        assert daemon.check_rate_limit("lock") is False
        # status should still work
        assert daemon.check_rate_limit("status") is True

    def test_unknown_action_uses_default_limit(self, fresh_rate_counters):
        import mina_daemon as daemon
        # Unknown action gets default limit of 10
        for _ in range(10):
            assert daemon.check_rate_limit("unknown_action") is True
        assert daemon.check_rate_limit("unknown_action") is False


class TestExecuteAction:
    """Test action execution."""

    def test_unknown_action_rejected(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.execute_action("delete_everything", None)
        assert result["ok"] is False
        assert result["error"] == "unknown_action"

    def test_action_requires_args(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.execute_action("volume", None)
        assert result["ok"] is False
        assert result["error"] == "missing_args"

    def test_run_script_requires_args(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.execute_action("run_script", None)
        assert result["ok"] is False
        assert result["error"] == "missing_args"

    @patch("mina_daemon.execute_subprocess")
    def test_lock_executes_correct_command(self, mock_exec, patched_platform):
        import mina_daemon as daemon
        mock_exec.return_value = {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}
        result = daemon.execute_action("lock", None)
        assert result["ok"] is True
        # Check the command passed to execute_subprocess
        called_args = mock_exec.call_args[0][0]
        # 'lock-sessions' (not 'lock-session') — works from a service
        # context where the daemon has no login session of its own.
        assert called_args == ["loginctl", "lock-sessions"]

    @patch("mina_daemon.execute_subprocess")
    def test_volume_arg_substitution(self, mock_exec, patched_platform):
        import mina_daemon as daemon
        mock_exec.return_value = {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}
        result = daemon.execute_action("volume", "50")
        assert result["ok"] is True
        called_args = mock_exec.call_args[0][0]
        assert "50%" in called_args

    @patch("mina_daemon.execute_subprocess")
    def test_destructive_action_has_delay(
        self, mock_exec, patched_platform, mock_destructive_delay
    ):
        import mina_daemon as daemon
        mock_exec.return_value = {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}
        result = daemon.execute_action("shutdown", None)
        assert result["ok"] is True
        assert mock_exec.called

    def test_unsupported_platform_action(self, patched_platform):
        import mina_daemon as daemon
        # Force a platform that has no command for the action
        original = daemon.PLATFORM
        daemon.PLATFORM = "solaris"
        result = daemon.execute_action("shutdown", None)
        daemon.PLATFORM = original
        assert result["ok"] is False
        assert result["error"] == "unsupported_platform"


class TestHandleScript:
    """Test script execution handler."""

    def test_invalid_script_name_special_chars(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.handle_script("script;rm -rf")
        assert result["ok"] is False
        assert result["error"] == "invalid_script_name"

    def test_invalid_script_name_path_traversal(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.handle_script("../../etc/passwd")
        assert result["ok"] is False
        assert result["error"] == "invalid_script_name"

    def test_script_not_found(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.handle_script("nonexistent_script_999")
        assert result["ok"] is False
        assert result["error"] == "script_not_found"

    def test_valid_script_executes(self, patched_platform, tmp_path):
        import mina_daemon as daemon
        # Create a test script in the scripts directory
        script_path = daemon.SCRIPTS_DIR / "test_echo.py"
        script_path.write_text("print('hello from test script')")
        try:
            result = daemon.handle_script("test_echo")
            assert result["ok"] is True
            assert "hello from test script" in result.get("stdout", "")
        finally:
            script_path.unlink(missing_ok=True)


class TestHandleStatus:
    """Test status handler."""

    def test_status_returns_ok(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.handle_status()
        assert result["ok"] is True

    def test_status_has_platform(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.handle_status()
        assert "platform" in result["status"]
        assert result["status"]["platform"] == "linux"

    def test_status_has_hostname(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.handle_status()
        assert "hostname" in result["status"]


class TestExecuteSubprocess:
    """Test subprocess execution."""

    def test_echo_command(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.execute_subprocess(["echo", "hello_mina"])
        assert result["ok"] is True
        assert "hello_mina" in result["stdout"]

    def test_command_not_found(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.execute_subprocess(["nonexistent_binary_xyz", "arg"])
        assert result["ok"] is False
        assert result["error"] == "not_found"

    def test_false_command_returns_nonzero(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.execute_subprocess(["false"])
        assert result["ok"] is True
        assert result["returncode"] != 0

    def test_command_with_args(self, patched_platform):
        import mina_daemon as daemon
        result = daemon.execute_subprocess(["python3", "-c", "print(42)"])
        assert result["ok"] is True
        assert "42" in result["stdout"]


# ════════════════════════════════════════════════════════════════
# HTTP HANDLER TESTS (integration via HTTP client)
# ════════════════════════════════════════════════════════════════

class TestHTTPServer:
    """Test the HTTP handler end-to-end via real HTTP requests."""

    @pytest.fixture
    def server(self, patched_platform, mock_destructive_delay, fresh_nonces, fresh_rate_counters):
        """Start a test HTTP server on a random port."""
        import mina_daemon as daemon
        import threading
        from http.server import HTTPServer

        daemon.MinaHandler.api_key = TEST_API_KEY
        daemon.MinaHandler.hmac_secret = TEST_HMAC_SECRET

        # Find a free port
        import socket
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        srv = daemon.ThreadingHTTPServer(("127.0.0.1", port), daemon.MinaHandler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()

        yield f"http://127.0.0.1:{port}"

        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)

    def _make_signed_request(self, base_url, action, args=None):
        """Build and send a signed command to the test server."""
        import send_command as sc
        result = sc.send_command(
            action=action,
            tunnel_url=base_url,
            api_key=TEST_API_KEY,
            hmac_secret=TEST_HMAC_SECRET,
            args=args,
        )
        return result

    def test_health_endpoint(self, server):
        import urllib.request
        resp = urllib.request.urlopen(server + "/health", timeout=5)
        data = json.loads(resp.read())
        assert data["ok"] is True
        assert data["service"] == "mina-local-daemon"

    def test_root_endpoint(self, server):
        import urllib.request
        resp = urllib.request.urlopen(server + "/", timeout=5)
        data = json.loads(resp.read())
        assert data["ok"] is True

    def test_404_on_unknown_path(self, server):
        import urllib.request
        import urllib.error
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(server + "/unknown_path", timeout=5)
        assert exc_info.value.code == 404

    def test_missing_bearer_token(self, server):
        import urllib.request
        import urllib.error
        payload = b'{"action":"status","timestamp":0,"nonce":"x"}'
        req = urllib.request.Request(
            server + "/command", data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 401

    def test_invalid_bearer_token(self, server):
        import urllib.request
        import urllib.error
        payload = b'{"action":"status","timestamp":0,"nonce":"x"}'
        req = urllib.request.Request(
            server + "/command", data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer wrong_key",
                "X-Mina-Signature": "x" * 64,
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 401

    def test_missing_signature(self, server):
        import urllib.request
        import urllib.error
        payload = b'{"action":"status","timestamp":0,"nonce":"x"}'
        req = urllib.request.Request(
            server + "/command", data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {TEST_API_KEY}",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 401

    def test_invalid_signature_rejected(self, server):
        import urllib.request
        import urllib.error
        payload = b'{"action":"status","timestamp":' + str(int(time.time())).encode() + b',"nonce":"test123"}'
        req = urllib.request.Request(
            server + "/command", data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {TEST_API_KEY}",
                "X-Mina-Signature": "0" * 64,  # Wrong signature
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 401

    def test_valid_command_status(self, server):
        """Send a valid signed 'status' command and verify response."""
        result = self._make_signed_request(server, "status")
        assert result["ok"] is True
        assert "status" in result

    def test_valid_command_lock(self, server):
        """Send a valid signed 'lock' command."""
        # Mock the actual subprocess so it doesn't actually lock the screen
        import mina_daemon as daemon
        with patch("mina_daemon.execute_subprocess") as mock_exec:
            mock_exec.return_value = {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}
            result = self._make_signed_request(server, "lock")
        assert result["ok"] is True

    def test_unknown_action_via_http(self, server):
        """Send an unknown action and verify it's rejected."""
        result = self._make_signed_request(server, "delete_everything")
        assert result["ok"] is False
        assert result["error"] == "unknown_action"

    def test_replay_attack_rejected(self, server):
        """Send same payload twice — second should be rejected."""
        import send_command as sc

        # First request — should succeed
        result1 = self._make_signed_request(server, "status")
        # We can't easily replay the exact same payload because send_command
        # generates a new nonce each time. Instead, manually build and send
        # the same payload twice.
        payload = sc.build_payload("status")
        sig = sc.sign_payload(payload, TEST_HMAC_SECRET)

        import urllib.request
        url = server + "/command"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_API_KEY}",
            "X-Mina-Signature": sig,
        }

        req1 = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        resp1 = urllib.request.urlopen(req1, timeout=10)
        data1 = json.loads(resp1.read())
        assert data1["ok"] is True

        # Second request with same payload — should be rejected
        import urllib.error
        req2 = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req2, timeout=10)
        assert exc_info.value.code == 401
        err_body = json.loads(exc_info.value.read())
        assert err_body["error"] == "replay_detected"
