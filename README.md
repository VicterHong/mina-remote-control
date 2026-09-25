# MINA — Remote Control for Your Home Machine

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/victer)
[![Saweria](https://img.shields.io/badge/Saweria-Support%20me-FAAE1D?logo=buymeacoffee&logoColor=white)](https://saweria.co/victer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests: 231 passing](https://img.shields.io/badge/tests-231%20passing-brightgreen.svg)](#tests)

**Turn your old laptop into a remotely-controllable machine — from Telegram, Discord, or any HTTP client.**

MINA is a lightweight, security-first daemon that lets an AI agent (or you) control a home computer remotely: shut it down, wake it up, open apps, take screenshots, run allowlisted scripts, and show a live system dashboard. It was built to run on **low-spec hardware** — a 2-4 GB RAM Bay Trail-class laptop — using ~25 MB of RAM.

```
Telegram / Discord / HTTP client
        │  "shut down my laptop" / "wake the NAS"
        ▼
  AI agent (e.g. Hermes)  ──HMAC-signed payload──▶  HTTPS tunnel
        │                                              │
        │                                              ▼
        │                                    mina_daemon.py (127.0.0.1:8765)
        │                                    ├─ verify token + HMAC + nonce
        │                                    ├─ check strict allowlist
        │                                    ├─ rate-limit per action
        │                                    └─ execute (shell=False)
        ▼
  OS action: shutdown · sleep · lock · wake-on-LAN · open app · screenshot · dashboard
```

## Why MINA?

| Feature | Why it matters |
|---------|----------------|
| **Security-first design** | Bearer token + HMAC-SHA256 on every request, replay protection (5-min window), strict command allowlist, per-action rate limits, `shell=False` everywhere. No arbitrary shell execution — ever. |
| **Low-spec friendly** | Runs in ~25 MB RSS with a 100 MB memory cap. Auto-disables heavy features (GUI automation) when RAM is low. Graceful degradation with circuit breakers. |
| **Zero-framework web UI** | Built-in admin UI (stdlib only): first-run setup, login, credential generator with one-time reveal, dashboard. No Django, no Flask, no Node. |
| **Cross-platform** | Windows, Linux, macOS. Power management, GUI control, and script execution all adapt per-platform. |
| **Wake-on-LAN built in** | Wake devices by name from a registry (or raw MAC). |
| **Tested** | **231 automated tests** covering core, extended, low-spec, and auth/UI paths. |

## Quick Start

### 1. Install dependencies

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — generate real secrets:
python3 -c "import secrets; print('mina_sk_' + secrets.token_urlsafe(32))"   # API key
python3 -c "import secrets; print(secrets.token_hex(32))"                    # HMAC secret
```

### 3. Run the daemon

```bash
python3 scripts/mina_daemon.py
```

First run: the daemon prints a **one-time setup token** in the log. Open `http://127.0.0.1:8765/ui/` to create your admin account and generate credentials. The full API key + secret are displayed **exactly once** — save them.

### 4. Send a command

```bash
# Structured mode
python3 scripts/send_command.py --action lock \
  --tunnel-url https://your-tunnel.example.com \
  --api-key "$MINA_API_KEY" --hmac-secret "$MINA_HMAC_SECRET"

# Natural language mode (Indonesian / English)
python3 scripts/send_command.py --nl "kunci layar" ...
python3 scripts/send_command.py --nl "wake the nas" ...
```

### 5. Install as a service (optional)

```bash
bash scripts/install_service.sh --user     # user service (GUI actions work)
sudo bash scripts/install_service.sh       # system service + polkit for power actions
```

Windows: `powershell -File scripts/install_service.ps1`

## Supported Commands

| Action | What it does | Notes |
|--------|-------------|-------|
| `shutdown` / `restart` / `sleep` / `hibernate` | Power management | 5-second confirmation delay for destructive actions |
| `lock` | Lock the screen | |
| `wake` | Wake-on-LAN magic packet | Device registry or raw MAC |
| `open_app` | Launch an allowlisted app | argv arrays, `shell=False` |
| `open_url` | Open URL in default browser | http/https/file only |
| `screenshot` | Capture the screen | Returns file path |
| `dashboard` | Live system dashboard (HTML) | CPU/RAM/disk/containers, auto-refresh |
| `status` | CPU/memory/disk/uptime snapshot | |
| `run_script` | Run allowlisted scripts | Only from `~/.mina/scripts/` |
| `gui_type` / `gui_key` / `gui_click` | GUI automation | Tier-2: needs `pyautogui` + graphical session |
| `volume` | Set system volume | Windows (nircmd) / Linux (amixer) |

## Security Model

MINA assumes the tunnel endpoint is hostile territory. Every layer:

1. **Transport** — HTTPS via Cloudflare Tunnel / ngrok (TLS 1.3)
2. **Authentication** — Bearer API token, constant-time comparison
3. **Integrity** — HMAC-SHA256 signature over the full request body
4. **Replay protection** — timestamp + nonce, 5-minute window
5. **Command safety** — strict allowlist; unknown actions rejected
6. **Rate limiting** — per-action hourly quotas (e.g. shutdown: 2/h)
7. **Script sandbox** — scripts only from `~/.mina/scripts/`, extension-allowlisted
8. **Execution** — `subprocess.run()` with arg arrays; **never** `shell=True`
9. **Audit log** — every command logged with timestamp, source, and result
10. **Web UI** — PBKDF2-SHA256 (100k iterations), CSRF tokens, HttpOnly+SameSite=Strict cookies, one-time credential reveal

## Tests

```bash
python3 -m pytest tests/ -q     # 231 tests
```

| Suite | Coverage |
|-------|----------|
| `test_mina.py` (93) | Core daemon: auth, allowlist, rate limits, handlers |
| `test_mina_extended.py` (57) | WoL, GUI, dashboard, send_command parsing |
| `test_mina_lowspec.py` (31) | Memory caps, Tier-2 degradation, installer artifacts |
| `test_mina_auth.py` (50) | Web UI: setup, login, credential rotation, sessions |

## Low-Spec Deployment

Designed to keep an old laptop useful. Details in [`LOWSPEC-DEPLOY.md`](LOWSPEC-DEPLOY.md).

- systemd limits: `MemoryMax=100M`, `Nice=10`, `IOSchedulingClass=idle`, `OOMPolicy=continue`
- GUI children detached outside the daemon cgroup so the memory cap never kills them
- Tier-2 circuit breaker: auto-disables after repeated failures or low free RAM
- Measured: **~25 MB RSS idle** (4× headroom under the cap)

## Documentation

- [`SKILL.md`](SKILL.md) — full command reference, configuration, architecture
- [`LOWSPEC-DEPLOY.md`](LOWSPEC-DEPLOY.md) — deployment runbook for weak hardware
- [`config/mina.yaml`](config/mina.yaml) — capability groups, safety policy, device registry
- [`config/commands.yaml`](config/commands.yaml) — action allowlist + rate limits

## Requirements

- Python 3.9+ (stdlib-heavy; only `psutil` + `PyYAML` required)
- Linux / macOS / Windows
- A tunnel (Cloudflare Tunnel or ngrok) if controlling from outside your LAN

## Support This Project

MINA is free and open source (MIT). If it's useful to you, you can support its development:

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/victer)
[![Saweria](https://img.shields.io/badge/Saweria-Support%20me-FAAE1D?logo=buymeacoffee&logoColor=white)](https://saweria.co/victer)

- ☕ **Ko-fi** — one-time or monthly: [ko-fi.com/victer](https://ko-fi.com/victer)
- 🇮🇩 **Saweria** — for Indonesian supporters: [saweria.co/victer](https://saweria.co/victer)

Every contribution keeps this project maintained and free for everyone.

## License

MIT — see [LICENSE](LICENSE).
