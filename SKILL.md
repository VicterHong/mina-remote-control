---
name: mina-workspace
description: "Use when user asks to control their laptop remotely: power (shutdown/restart/sleep/WoL), screen & GUI (open apps, lock, dashboard), scripts. Parses natural language (ID/EN) to system commands."
tags: [system-control, remote, mina, automation, power-management, wol, gui-automation, telegram, discord]
category: system-control
version: 1.3.0
author: CodeBuddy Code
---

# Mina — Personal Smart Consultant

Remote device control system — translates natural language commands from Telegram/Discord chat into structured payloads sent to a local daemon running on the user's laptop via secure webhook (Cloudflare Tunnel / ngrok).

**Capabilities:** system power management (shutdown/restart/sleep/hibernate/Wake-on-LAN) · screen & GUI automation (open apps/URLs, lock, screenshot, type/keys/click, monitoring dashboard) · allowlisted script execution.

## When to Use

✅ Use when:
- User says "tutup laptop", "matikan PC", "lock screen", "sleep", "hibernasi"
- User says "bangunkan [device]" / "wake [device]" → Wake-on-LAN magic packet
- User says "buka aplikasi [nama]" / "open app [name]" → launch allowlisted app
- User says "buka url [link]" / "open url" → open URL in default browser
- User says "tampilkan dashboard" / "monitoring" → CPU/RAM/disk/containers dashboard
- User says "ketik [teks]", "tekan tombol [key]", "klik [x,y]" → Tier-2 GUI automation
- User says "jalankan skrip [nama]" to run a whitelisted local script
- User says "cek status laptop" for health check
- User asks to control volume or take screenshot

❌ Never use for:
- Arbitrary command execution (only allowlisted actions)
- Accessing files or reading personal data remotely
- Any action not in the command allowlist

## Architecture

```
User (Telegram/Discord)
    │  "matikan PC" / "bangunkan nas" / "buka aplikasi browser"
    ▼
Hermes Agent
    │ parses natural language → structured payload
    │ signs payload with HMAC-SHA256
    ▼
HTTPS Webhook (Cloudflare Tunnel / ngrok)
    │
    ▼
mina_daemon.py (on laptop, 127.0.0.1:8765)
    │ verifies HMAC signature + API token + nonce/rate limit
    │ checks command against allowlist
    │ dispatches to handler:
    ├─ Power     → systemctl / shutdown / pmset
    ├─ WoL       → scripts/wol.py (UDP magic packet)
    ├─ GUI       → scripts/gui_automation.py (argv launchers + pyautogui)
    ├─ Dashboard → scripts/dashboard.py (HTML + browser)
    └─ Scripts   → ~/.mina/scripts/ (allowlist extension)
    ▼
OS Action (shutdown / lock / sleep / wake / open / type / dashboard)
```

## Security Model (Defense-in-Depth)

| Layer | Control |
|-------|---------|
| Transport | HTTPS via Cloudflare Tunnel (TLS 1.3) |
| Authentication | Bearer API token in header |
| Integrity | HMAC-SHA256 signature on every request body |
| Replay protection | Timestamp + nonce (5 min window) |
| Command safety | Strict allowlist — no arbitrary execution |
| Rate limiting | Per-action hourly quotas (e.g. shutdown: 2/h) |
| Script safety | Only scripts from `~/.mina/scripts/` directory |
| Execution | `subprocess.run()` with arg arrays — never `shell=True` |
| Logging | All commands logged with timestamp, source, result |

## Command Reference

### Natural Language → Payload Mapping

| User Says (ID/EN) | action | platform | Command |
|-------------------|--------|----------|---------|
| "matikan PC" / "shutdown" | `shutdown` | Windows | `shutdown /s /t 1` |
| "matikan PC" / "shutdown" | `shutdown` | Linux | `systemctl poweroff` |
| "tutup laptop" / "sleep" | `sleep` | Windows | `rundll32.exe powrprof.dll,SetSuspendState 0,1,0` |
| "tutup laptop" / "sleep" | `sleep` | Linux | `systemctl suspend` |
| "lock screen" / "kunci layar" | `lock` | Windows | `rundll32.exe user32.dll,LockWorkStation` |
| "lock screen" / "kunci layar" | `lock` | Linux | `loginctl lock-session` |
| "hibernasi" / "hibernate" | `hibernate` | Windows | `shutdown /h` |
| "hibernasi" / "hibernate" | `hibernate` | Linux | `systemctl hibernate` |
| "restart" / "reboot" | `restart` | Windows | `shutdown /r /t 1` |
| "restart" / "reboot" | `restart` | Linux | `systemctl reboot` |
| **"bangunkan nas" / "wake nas"** | `wake` | Any | WoL magic packet → device in `devices:` registry (or raw MAC) |
| **"buka aplikasi browser" / "open app terminal"** | `open_app` | Any | Launches allowlisted app from `apps:` (argv, shell=False) |
| **"buka url https://..." / "open url ..."** | `open_url` | Any | `xdg-open` / `open` / `start` (http/https/file only) |
| **"tampilkan dashboard" / "monitoring"** | `dashboard` | Any | Generates HTML dashboard + opens browser (auto-refresh 30s) |
| **"ketik [teks]" / "type ..."** | `gui_type` | Any | Tier-2: pyautogui types into focused window |
| **"tekan tombol ctrl+alt+l" / "press key"** | `gui_key` | Any | Tier-2: pyautogui key/combo |
| **"klik 100,200" / "click"** | `gui_click` | Any | Tier-2: pyautogui click at x,y or current |
| "jalankan skrip [nama]" / "run script [name]" | `run_script` | Any | Runs `~/.mina/scripts/[name].sh` or `.bat` |
| "cek status" / "status" | `status` | Any | Returns CPU/mem/disk/uptime |
| "screenshot" | `screenshot` | Any | Captures screen, returns file path |
| "volume [0-100]" | `volume` | Windows | `nircmd setsysvolume N` |
| "volume [0-100]" | `volume` | Linux | `amixer set Master N%` |

### Capability Tiers

- **Tier 1** (no extra deps): `lock`, `screenshot`, `open_app`, `open_url`, `dashboard`, `wake` — run with stdlib + platform launchers only.
- **Tier 2** (needs `pyautogui` + graphical session): `gui_type`, `gui_key`, `gui_click`. Without pyautogui they return a clean `pyautogui_missing` error; without DISPLAY/WAYLAND_DISPLAY they return `no_display`.

### Wake-on-LAN Notes

- A sleeping machine cannot receive tunnel commands — to wake THE laptop itself, run `wol.py` (or the daemon) on another always-on LAN device.
- `wake <name>` works against devices registered in `config/mina.yaml` → `devices:` (mac, optional broadcast/port). Raw MACs are also accepted.
- Hardware prerequisites: WoL enabled in BIOS/UEFI + NIC (`ethtool wol g` on Linux).

## Configuration Files

| File | Purpose |
|------|---------|
| `config/commands.yaml` | Action allowlist (16 actions) + per-action rate limits + scripts dir |
| `config/mina.yaml` | **Agent config**: identity, capability groups, safety policy, `devices:` (WoL registry), `apps:` (GUI allowlist), `os_access` (required libraries/binaries), activation steps |
| `.env.example` | Credential template (tunnel URL, API key, HMAC secret) |

## How to Send a Command

Use the `send_command.py` script:

```bash
python3 ./scripts/send_command.py \
  --action shutdown \
  --tunnel-url https://your-tunnel.example.com \
  --api-key "$MINA_API_KEY" \
  --hmac-secret "$MINA_HMAC_SECRET"
```

Natural language mode (parses ID/EN text locally):

```bash
python3 .../send_command.py --nl "bangunkan nas" --tunnel-url ... --api-key ... --hmac-secret ...
python3 .../send_command.py --nl "buka aplikasi browser" ...
python3 .../send_command.py --nl "tampilkan dashboard" ...
```

## Utility Scripts

| Script | Usage |
|--------|-------|
| `scripts/wol.py` | `python3 wol.py --device nas` · `--mac AA:BB:...` · `--list` |
| `scripts/gui_automation.py` | `python3 gui_automation.py --check` (backend capability report) |
| `scripts/dashboard.py` | `python3 dashboard.py --open --interval 30` |
| `scripts/test_connection.py` | Probe daemon reachability through the tunnel |

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MINA_TUNNEL_URL` | HTTPS endpoint of Cloudflare Tunnel / ngrok | `https://abc.trycloudflare.com` |
| `MINA_API_KEY` | Bearer token for daemon auth | `mina_sk_...` (32+ chars) |
| `MINA_HMAC_SECRET` | HMAC-SHA256 signing secret | 64-char random hex |

Generate secrets:
```bash
python3 -c "import secrets; print('mina_sk_' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## OS Access Layer (what MINA needs to control the laptop fully)

**Python:** `psutil` (metrics, required), `pyyaml` (configs, required), `pyautogui` (Tier-2 GUI, optional), `Pillow` (Windows screenshots, optional).

**System binaries:**
- Linux: `systemctl`, `loginctl`, `xdg-open`, `xdotool`, `wmctrl`, `scrot`, `amixer` → `sudo apt install xdg-utils xdotool wmctrl scrot alsa-utils`
- macOS: `pmset`, `open`, `osascript`, `screencapture` (built-in)
- Windows: `shutdown`, `rundll32`, `nircmd` (volume, optional)

**OS APIs:** systemd D-Bus (polkit rights for power), X11/Wayland session (Wayland restricts synthetic input → `ydotool` for Tier-2), macOS Accessibility permission, Windows powercfg for sleep/hibernate.

## Web UI — Login & Credential Generator (v1.3.0)

The daemon serves its own lightweight web UI on the same port (stdlib only,
no framework, no extra service):

| Route | Purpose |
|-------|---------|
| `GET /` | redirect → setup / dashboard / login |
| `GET/POST /ui/setup` | first-run admin account (needs one-time setup token from daemon log) |
| `GET/POST /ui/login` | username + password sign-in (rate-limited: 5 fails/5 min) |
| `GET /ui/dashboard` | masked keys + **"Generate API & Secret Key"** button |
| `POST /ui/generate` | rotate credentials, hot-inject into daemon, arm one-time reveal |
| `POST /ui/logout` | destroy session |

**One-time display contract:** after generating, the FULL api key + secret
render exactly once (the very next dashboard view in that session), then are
dropped from the session — refresh/close/re-login shows only
`mina_sk_********` / `********` forever.

**Storage (low-spec, chmod 600, atomic writes):**
- `~/.mina/auth.json` — PBKDF2-SHA256 (default 100k iterations, `MINA_AUTH_ITERATIONS` to tune down on weak CPU), no plaintext
- `~/.mina/credentials.env` — `MINA_API_KEY` + `MINA_HMAC_SECRET`; loaded at daemon boot when env vars are absent
- Sessions: in-memory, capped (10), lazy expiry (30 min idle / 12 h absolute) — no threads, no timers

**Security properties:**
- Setup requires the one-time token printed in the daemon log (blocks remote claim via tunnel)
- Unconfigured daemon: `/command` returns 503 `not_configured` — empty-key bypass impossible
- CSRF token required on generate/logout; cookies `HttpOnly; SameSite=Strict`
- Timing-equalized login (dummy PBKDF2 on unknown username); constant-time compares
- Credential rotation is instant: the old pair is rejected the moment a new one is generated
- Disable entirely with `MINA_WEBUI=off` (daemon then requires env credentials as before)

**Measured (with web UI + auth loaded):** RSS ≈ 25 MB — well under the 100M cap.

## Tests

```bash
cd the repository root
python3 -m pytest tests/ -q   # 231 tests: 93 core + 57 extended + 31 low-spec + 50 auth/UI
```

## Low-Spec Deployment (weak laptops: Bay Trail-class low-spec)

Full runbook: `LOWSPEC-DEPLOY.md`. Summary:

**Resource limiting (systemd, low-spec profile — default in installer):**
```
MemoryMax=100M   MemoryHigh=80M   MemorySwapMax=0
CPUWeight=20     Nice=10          IOSchedulingClass=idle
OOMPolicy=continue   # a killed child never takes the daemon down
```
- `bash scripts/install_service.sh --user` → user service (GUI actions work; `loginctl enable-linger $USER`)
- `sudo bash scripts/install_service.sh` → system service + polkit rule for power actions
- Windows: `install_service.ps1` sets `BELOW_NORMAL_PRIORITY_CLASS` + CPU affinity (last core)
- Reference unit: `scripts/mina-daemon.service.example`
- GUI children (browser etc.) are detached OUTSIDE the daemon cgroup via `systemd-run --user --scope` so the 100M cap never OOM-kills them.

**Polling & timeout tuning** (`config/mina.yaml` → `performance:`, env overrides win):
| Knob | Low-spec value | Env override |
|------|---------------|--------------|
| status CPU sample | 0.3s (was 1.0s) | `MINA_STATUS_CPU_INTERVAL` |
| dashboard refresh | 60s (was 30s) | `MINA_DASHBOARD_REFRESH` |
| subprocess timeout | 20s (was 30s) | `MINA_CMD_TIMEOUT` |
| log rotation | 1MB × 3 files | — (built-in) |

**Graceful degradation (Tier-2 circuit breaker + memory guard):**
- `performance.tier2.enabled: false` → Tier-2 off by config on weak hardware; Tier-1 stays full.
- `MINA_TIER2=on/off` env override; `MINA_TIER2_MIN_FREE_MB` (default 150) auto-disables Tier-2 when free RAM is low.
- After `max_consecutive_failures` (default 2) import/runtime failures, Tier-2 auto-disables for the daemon's lifetime — daemon never crashes.
- `status` output reports `tier2_enabled` + `tier2_reason` for observability; `/health` reports `tier2_enabled`.

**Measured:** daemon RSS ≈ 25–35 MB idle (3× headroom under the 100M cap); `MemoryMax` enforcement verified (200MB alloc → SIGKILL 137; 20MB workload survives).

## Safety Rules

1. **Never** send arbitrary shell commands — only allowlisted actions
2. **Always** verify HMAC signature before trusting any response
3. **Never** log API keys or HMAC secrets in plaintext
4. **Always** include a 5-second confirmation delay for destructive actions (shutdown, restart)
5. **Never** enable `shell=True` in subprocess calls
6. **Always** keep `open_url` to http/https/file schemes; app names are sanitized to `[a-zA-Z0-9_-]`

## References

- Cloudflare Tunnel docs: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
- ngrok docs: https://ngrok.com/docs
- Python hmac module: https://docs.python.org/3/library/hmac.html
- subprocess security: https://docs.python.org/3/library/subprocess.html#security-considerations
- Wake-on-LAN spec: https://en.wikipedia.org/wiki/Wake-on-LAN
