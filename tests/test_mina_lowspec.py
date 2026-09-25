"""
Test suite for MINA low-spec deployment profile (Bay Trail-class low-spec).

Covers the three production-readiness requirements:
  1. Resource limiting      — perf knobs resolve correctly; launcher
                              detachment (cgroup escape) logic.
  2. Polling & timeout      — slowed refresh/sample defaults; config-driven.
  3. Graceful degradation   — Tier-2 circuit breaker + memory guard;
                              daemon survives Tier-2 failures; Tier-1 intact.

Run:
    cd the repository root
    python3 -m pytest tests/test_mina_lowspec.py -v
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture
def fresh_tier2_state():
    """Reset the Tier-2 circuit breaker around each test."""
    import mina_daemon as d
    original = dict(d.TIER2_STATE)
    yield d
    d.TIER2_STATE.clear()
    d.TIER2_STATE.update(original)


@pytest.fixture
def patched_platform():
    """Patch PLATFORM to 'linux' for deterministic launcher tests."""
    import mina_daemon as d
    original = d.PLATFORM
    d.PLATFORM = "linux"
    yield d
    d.PLATFORM = original


# ════════════════════════════════════════════════════════════════
# 1. POLLING & TIMEOUT OPTIMIZATION
# ════════════════════════════════════════════════════════════════

class TestPerfProfile:
    def test_perf_defaults_loaded_from_mina_yaml(self):
        """mina.yaml performance: block must drive the daemon defaults."""
        import mina_daemon as d
        # Low-spec profile ships these values in config/mina.yaml
        assert d.STATUS_CPU_SAMPLE_INTERVAL == pytest.approx(0.3)
        assert d.DASHBOARD_REFRESH_SECONDS == 60
        assert d.CMD_TIMEOUT_SECONDS == 20

    def test_dashboard_refresh_slower_than_original_30s(self):
        import mina_daemon as d
        assert d.DASHBOARD_REFRESH_SECONDS >= 30

    def test_cmd_timeout_shorter_than_original_30s(self):
        import mina_daemon as d
        assert d.CMD_TIMEOUT_SECONDS <= 30

    def test_status_cpu_sample_not_longer_than_original(self):
        import mina_daemon as d
        assert d.STATUS_CPU_SAMPLE_INTERVAL <= 0.5

    def test_env_override_status_interval(self):
        """MINA_STATUS_CPU_INTERVAL must win over the yaml value."""
        import importlib
        import mina_daemon as d
        with patch.dict("os.environ", {"MINA_STATUS_CPU_INTERVAL": "0.1"}):
            importlib.reload(d)
            assert d.STATUS_CPU_SAMPLE_INTERVAL == pytest.approx(0.1)
        importlib.reload(d)  # restore module state for other tests

    def test_execute_subprocess_uses_configured_timeout(self):
        import mina_daemon as d
        with patch("mina_daemon.subprocess.run") as mock_run:
            mock_run.return_value = type(
                "R", (), {"returncode": 0, "stdout": "x", "stderr": ""})()
            d.execute_subprocess(["echo", "hi"])
            kwargs = mock_run.call_args[1]
            assert kwargs["timeout"] == d.CMD_TIMEOUT_SECONDS

    def test_timeout_message_reports_configured_value(self):
        import subprocess as sp
        import mina_daemon as d
        with patch("mina_daemon.subprocess.run",
                   side_effect=sp.TimeoutExpired(cmd="x", timeout=1)):
            result = d.execute_subprocess(["sleep", "999"])
            assert result["ok"] is False
            assert str(d.CMD_TIMEOUT_SECONDS) in result["detail"]

    def test_dashboard_interval_wired_into_generation_command(self):
        """handle_dashboard must pass the configured interval to dashboard.py."""
        import mina_daemon as d
        captured = {}

        def fake_exec(cmd):
            captured["cmd"] = cmd
            return {"ok": True, "returncode": 0, "stdout": "{}", "stderr": ""}

        with patch("mina_daemon.execute_subprocess", side_effect=fake_exec), \
             patch("mina_daemon.execute_launcher",
                   return_value={"ok": True, "detached": True}):
            d.handle_dashboard()
        assert "--interval" in captured["cmd"]
        idx = captured["cmd"].index("--interval")
        assert captured["cmd"][idx + 1] == str(d.DASHBOARD_REFRESH_SECONDS)


# ════════════════════════════════════════════════════════════════
# 2. GRACEFUL DEGRADATION — Tier-2 circuit breaker
# ════════════════════════════════════════════════════════════════

class TestTier2CircuitBreaker:
    def test_tier2_disabled_by_low_spec_config(self, fresh_tier2_state):
        """mina.yaml ships tier2.enabled=false for low-spec machines."""
        d = fresh_tier2_state
        assert d.TIER2_STATE["enabled"] is False
        assert d.TIER2_STATE["reason"] == "tier2_disabled_by_config"

    def test_gui_action_returns_clean_error_when_disabled(self, fresh_tier2_state):
        d = fresh_tier2_state
        result = d.handle_gui_type("hello")
        assert result["ok"] is False
        assert "tier2" in result["error"]
        # Must be an informative error, never an exception/crash
        assert "Tier-1" in result["detail"]

    def test_gui_key_clean_error_when_disabled(self, fresh_tier2_state):
        d = fresh_tier2_state
        result = d.handle_gui_key("enter")
        assert result["ok"] is False
        assert "tier2" in result["error"]

    def test_gui_click_clean_error_when_disabled(self, fresh_tier2_state):
        d = fresh_tier2_state
        result = d.handle_gui_click("10,20")
        assert result["ok"] is False
        assert "tier2" in result["error"]

    def test_gui_click_bad_args_reported_even_when_tier2_off(self, fresh_tier2_state):
        """Arg validation happens before the gate — precise errors."""
        d = fresh_tier2_state
        result = d.handle_gui_click("not-coords")
        assert result["ok"] is False
        assert result["error"] == "invalid_args"

    def test_circuit_opens_after_repeated_failures(self, fresh_tier2_state):
        d = fresh_tier2_state
        d.TIER2_STATE.update({"enabled": True, "failures": 0, "reason": None})
        for _ in range(d.TIER2_MAX_FAILURES):
            d.tier2_record_failure("pyautogui_missing")
        assert d.TIER2_STATE["enabled"] is False
        assert d.TIER2_STATE["reason"] == "pyautogui_missing"

    def test_success_resets_failure_counter(self, fresh_tier2_state):
        d = fresh_tier2_state
        d.TIER2_STATE.update({"enabled": True, "failures": 0, "reason": None})
        d.tier2_record_failure("no_display")
        d.tier2_record_success()
        assert d.TIER2_STATE["failures"] == 0
        assert d.TIER2_STATE["enabled"] is True

    def test_daemon_survives_pyautogui_missing(self, fresh_tier2_state):
        """Tier-2 enabled but pyautogui absent → clean error, no crash."""
        d = fresh_tier2_state
        d.TIER2_STATE.update({"enabled": True, "failures": 0, "reason": None})
        with patch.object(d, "memory_guard",
                          return_value={"checked": True, "action": "none"}), \
             patch.object(d, "tier2_available", return_value=(True, None)), \
             patch("mina_daemon._load_gui_module") as mock_gui:
            fake_gui = type("G", (), {})()
            fake_gui.type_text = lambda t: {"ok": False,
                                            "error": "pyautogui_missing",
                                            "detail": "pip install pyautogui"}
            mock_gui.return_value = fake_gui
            result = d.handle_gui_type("hi")
        assert result["ok"] is False
        assert result["error"] == "pyautogui_missing"
        # And the failure was counted toward the breaker
        assert d.TIER2_STATE["failures"] == 1

    def test_status_reports_tier2_state(self, fresh_tier2_state):
        d = fresh_tier2_state
        result = d.handle_status()
        assert result["ok"] is True
        assert "tier2_enabled" in result["status"]
        if not result["status"]["tier2_enabled"]:
            assert "tier2_reason" in result["status"]

    def test_tier1_unaffected_by_tier2_disable(self, fresh_tier2_state):
        """Core Tier-1 actions keep working while Tier-2 is off."""
        d = fresh_tier2_state
        assert d.execute_action("status", None)["ok"] is True
        with patch("mina_daemon.execute_subprocess") as mock_exec:
            mock_exec.return_value = {"ok": True, "returncode": 0,
                                      "stdout": "", "stderr": ""}
            assert d.execute_action("lock", None)["ok"] is True
            assert d.execute_action("volume", "50")["ok"] is True


# ════════════════════════════════════════════════════════════════
# 3. GRACEFUL DEGRADATION — memory guard
# ════════════════════════════════════════════════════════════════

class TestMemoryGuard:
    def test_low_memory_disables_tier2(self, fresh_tier2_state):
        d = fresh_tier2_state
        d.TIER2_STATE.update({"enabled": True, "failures": 0, "reason": None})
        fake_mem = type("M", (), {"available": 50 * 1024 * 1024})()
        with patch.object(d.psutil, "virtual_memory", return_value=fake_mem):
            report = d.memory_guard()
        assert report["action"] == "tier2_disabled_low_memory"
        assert d.TIER2_STATE["enabled"] is False

    def test_plenty_of_memory_keeps_tier2(self, fresh_tier2_state):
        d = fresh_tier2_state
        d.TIER2_STATE.update({"enabled": True, "failures": 0, "reason": None})
        fake_mem = type("M", (), {"available": 2048 * 1024 * 1024})()
        with patch.object(d.psutil, "virtual_memory", return_value=fake_mem):
            report = d.memory_guard()
        assert report["action"] == "none"
        assert d.TIER2_STATE["enabled"] is True

    def test_memory_guard_never_raises(self, fresh_tier2_state):
        d = fresh_tier2_state
        with patch.object(d.psutil, "virtual_memory",
                          side_effect=RuntimeError("boom")):
            report = d.memory_guard()  # must not raise
        assert isinstance(report, dict)

    def test_gate_returns_low_memory_error(self, fresh_tier2_state):
        d = fresh_tier2_state
        d.TIER2_STATE.update({"enabled": True, "failures": 0, "reason": None})
        with patch.object(d, "memory_guard",
                          return_value={"checked": True, "available_mb": 40,
                                        "action": "tier2_disabled_low_memory"}):
            result = d._tier2_gate()
        assert result is not None
        assert result["error"] == "tier2_disabled_low_memory"
        assert "40" in result["detail"]


# ════════════════════════════════════════════════════════════════
# 4. RESOURCE LIMITING — launcher cgroup escape
# ════════════════════════════════════════════════════════════════

class TestLauncherDetachment:
    def test_launcher_falls_back_without_user_manager(self, patched_platform):
        """No XDG_RUNTIME_DIR/systemd dir → plain detached Popen."""
        import mina_daemon as d
        with patch.dict("os.environ", {"XDG_RUNTIME_DIR": ""}, clear=False), \
             patch("mina_daemon.subprocess.Popen") as mock_popen:
            mock_popen.return_value = type("P", (), {"pid": 1234})()
            result = d.execute_launcher(["xdg-open", "https://x"])
            called = mock_popen.call_args[0][0]
            assert called == ["xdg-open", "https://x"]
            assert mock_popen.call_args[1].get("start_new_session") is True
            assert result["detached"] is False

    def test_launcher_uses_systemd_run_when_manager_reachable(self, patched_platform):
        import mina_daemon as d
        with patch.dict("os.environ", {"XDG_RUNTIME_DIR": "/run/user/1000"}), \
             patch("mina_daemon.os.path.isdir", return_value=True), \
             patch("mina_daemon.shutil.which", return_value="/usr/bin/systemd-run"), \
             patch("mina_daemon.subprocess.Popen") as mock_popen:
            mock_popen.return_value = type("P", (), {"pid": 1234})()
            result = d.execute_launcher(["xdg-open", "https://x"])
            called = mock_popen.call_args[0][0]
            assert called[:4] == ["systemd-run", "--user", "--scope", "--quiet"]
            assert result["detached"] is True

    def test_launcher_never_uses_shell(self, patched_platform):
        import mina_daemon as d
        with patch("mina_daemon.subprocess.Popen") as mock_popen:
            mock_popen.return_value = type("P", (), {"pid": 1})()
            d.execute_launcher(["xdg-open", "https://x"])
            assert mock_popen.call_args[1]["shell"] is False

    def test_open_url_uses_launcher(self, patched_platform):
        import mina_daemon as d
        with patch("mina_daemon.execute_launcher") as mock_launch, \
             patch("mina_daemon.execute_subprocess") as mock_exec:
            mock_launch.return_value = {"ok": True, "detached": True}
            result = d.handle_open_url("https://example.com")
            assert result["ok"] is True
            assert mock_launch.called
            assert not mock_exec.called  # never a blocking subprocess


# ════════════════════════════════════════════════════════════════
# 5. CONFIG FILES — presence + values used at install time
# ════════════════════════════════════════════════════════════════

class TestDeploymentArtifacts:
    def _skill_dir(self):
        return Path(__file__).parent.parent

    def test_service_example_has_memory_cap(self):
        unit = (self._skill_dir() / "scripts" / "mina-daemon.service.example").read_text()
        assert "MemoryMax=100M" in unit
        assert "MemoryHigh=80M" in unit
        assert "Nice=10" in unit
        assert "OOMPolicy=continue" in unit

    def test_service_example_limits_in_correct_sections(self):
        unit = (self._skill_dir() / "scripts" / "mina-daemon.service.example").read_text()
        service_block = unit.split("[Service]", 1)[1].split("[Install]", 1)[0]
        unit_block = unit.split("[Unit]", 1)[1].split("[Service]", 1)[0]
        # StartLimit* belong in [Unit]; resource caps in [Service]
        assert "StartLimitBurst" in unit_block
        assert "StartLimitBurst" not in service_block
        assert "MemoryMax" in service_block

    def test_installer_supports_low_spec_profile(self):
        sh = (self._skill_dir() / "scripts" / "install_service.sh").read_text()
        assert "low-spec" in sh
        assert "MemoryMax" in sh
        assert "OOMPolicy=continue" in sh
        assert "--user" in sh  # user-service mode for GUI-capable installs

    def test_ps1_installer_has_priority_profile(self):
        ps1 = (self._skill_dir() / "scripts" / "install_service.ps1").read_text()
        assert "BELOW_NORMAL_PRIORITY_CLASS" in ps1
        assert "AppAffinity" in ps1

    def test_mina_yaml_performance_block(self):
        import yaml
        cfg = yaml.safe_load(
            (self._skill_dir() / "config" / "mina.yaml").read_text())
        perf = cfg["performance"]
        assert perf["dashboard_refresh_s"] == 60
        assert perf["cmd_timeout_s"] == 20
        assert perf["tier2"]["enabled"] is False
        assert perf["tier2"]["min_free_memory_mb"] == 150


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
