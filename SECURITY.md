# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of these private channels:

1. **GitHub Private Vulnerability Reporting** — go to the [Security tab](https://github.com/VicterHong/mina-remote-control/security/advisories/new) and click "Report a vulnerability".
2. **Email** — contact the maintainer directly (see GitHub profile: [@VicterHong](https://github.com/VicterHong)).

You can expect:

- **Acknowledgement** within 72 hours.
- **Status update** within 7 days (accepted / needs more info / declined with rationale).
- **Fix or mitigation** for accepted reports as soon as practical — MINA is a security-first project, so vulnerabilities are prioritized.

## Scope

MINA is a remote-control daemon. The most valuable reports are those affecting:

- **Authentication bypass** — defeating the bearer token, HMAC signature, or replay protection
- **Command allowlist bypass** — executing actions outside `config/commands.yaml`
- **Injection** — shell injection, path traversal in `run_script`, argument injection
- **Web UI** — session handling, CSRF, credential reveal logic, PBKDF2 implementation
- **Tunnel exposure** — anything reachable pre-authentication

Out of scope:

- Vulnerabilities requiring physical access to the machine
- Issues in dependencies (report those upstream; Dependabot tracks them here)
- Social engineering
- The inherent risk of opening a tunnel to a home machine (documented design tradeoff — use strong secrets and keep the daemon updated)

## Design Principles (why MINA is built this way)

- **No arbitrary command execution.** Only allowlisted actions; `subprocess.run()` with arg arrays, never `shell=True`.
- **Defense in depth.** Bearer token + HMAC-SHA256 + timestamp/nonce window + per-action rate limits.
- **Least privilege.** Scripts restricted to `~/.mina/scripts/` with extension allowlist.
- **Fail closed.** Unconfigured daemon returns `503 not_configured` — no empty-key bypass.
- **Audit everything.** Every command is logged with timestamp, source, and result.

## Security Checklist for Deployers

- [ ] Generate strong secrets (`mina_sk_...` 32+ chars, 64-char hex HMAC secret) — never reuse
- [ ] Keep `.env` out of version control (already in `.gitignore`)
- [ ] Run the daemon as a non-root user service where possible
- [ ] Enable Tier-2 (GUI automation) only if you need it — it needs a graphical session
- [ ] Update regularly — Dependabot is enabled on this repo
- [ ] Review the allowlist in `config/commands.yaml` before exposing via a tunnel
