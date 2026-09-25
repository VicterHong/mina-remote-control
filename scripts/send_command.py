#!/usr/bin/env python3
"""
Mina Command Sender — runs on the Hermes server side.

Parses natural language commands, builds a structured JSON payload,
signs it with HMAC-SHA256, and sends it to the local daemon on the
user's laptop via the HTTPS tunnel endpoint.

Usage:
    python3 send_command.py --action shutdown --tunnel-url https://abc.trycloudflare.com
    python3 send_command.py --action lock --tunnel-url https://abc.trycloudflare.com
    python3 send_command.py --action run_script --args backup_db --tunnel-url ...

Environment variables (or CLI flags):
    MINA_TUNNEL_URL   — HTTPS endpoint (Cloudflare Tunnel / ngrok)
    MINA_API_KEY      — Bearer token for daemon auth
    MINA_HMAC_SECRET  — HMAC-SHA256 signing secret
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path


# ── Natural language → action mapping ───────────────────────────

NL_PATTERNS = [
    # (keywords, action, requires_arg)
    (["matikan pc", "matikan laptop", "shutdown", "turn off"], "shutdown", False),
    (["restart", "reboot", "mulai ulang"], "restart", False),
    (["tutup laptop", "sleep", "tidur", "suspend"], "sleep", False),
    (["hibernasi", "hibernate"], "hibernate", False),
    (["lock", "kunci layar", "lock screen", "kunci"], "lock", False),
    (["status", "cek status", "health"], "status", False),
    (["screenshot", "tangkap layar", "capture"], "screenshot", False),
    (["volume"], "volume", True),  # extract number
    (["jalankan skrip", "run script", "eksekusi skrip"], "run_script", True),
    # ── Power: Wake-on-LAN ───────────────────────────────────────
    (["bangunkan", "wake up", "wake", "wol"], "wake", True),
    # ── Screen & GUI ─────────────────────────────────────────────
    (["buka aplikasi", "open app", "buka app"], "open_app", True),
    (["buka url", "buka website", "open url", "buka situs"], "open_url", True),
    (["dashboard", "tampilkan dashboard", "show dashboard", "monitoring"],
     "dashboard", False),
    (["ketik", "type "], "gui_type", True),
    (["tekan tombol", "press key", "hotkey"], "gui_key", True),
    (["klik", "click"], "gui_click", True),
]

# Actions whose argument is a free-text tail (not a name/number)
FREETEXT_ACTIONS = {"gui_type", "open_url"}


def _extract_tail(text: str, kw: str) -> str:
    """Return the text after the matched keyword (case-insensitive), original case kept."""
    idx = text.lower().find(kw.lower())
    if idx < 0:
        return ""
    return text[idx + len(kw):].strip()


def parse_natural_language(text: str) -> tuple[str, str | None]:
    """
    Parse natural language command text into (action, args).
    Returns ("unknown", None) if no match.
    """
    text_lower = text.lower().strip()

    for keywords, action, requires_arg in NL_PATTERNS:
        for kw in keywords:
            if kw in text_lower:
                if not requires_arg:
                    return action, None

                # Extract argument (number for volume, name for script,
                # free text for gui_type/open_url, name/MAC for wake, etc.)
                if action == "volume":
                    # Find integer 0-100
                    import re
                    match = re.search(r"\b(\d{1,3})\b", text_lower)
                    if match:
                        vol = int(match.group(1))
                        if 0 <= vol <= 100:
                            return action, str(vol)
                    return "error: volume requires number 0-100", None

                if action == "run_script":
                    # Extract script name after keyword
                    idx = text_lower.find(kw)
                    script_name = text[idx + len(kw):].strip()
                    if script_name:
                        # Sanitize: only alphanumeric + underscore + hyphen
                        import re
                        clean = re.sub(r"[^a-zA-Z0-9_-]", "", script_name)
                        if clean:
                            return action, clean
                    return "error: script name required", None

                if action in FREETEXT_ACTIONS:
                    # Keep original casing (URLs, typed text are case-sensitive)
                    tail = _extract_tail(text, kw)
                    if tail:
                        return action, tail
                    return f"error: {action} requires text", None

                if action in ("open_app", "wake"):
                    # Name or MAC: take the tail, sanitize for app names only
                    tail = _extract_tail(text, kw)
                    if not tail:
                        return f"error: {action} requires a name", None
                    if action == "wake":
                        # Allow MAC (colons/hyphens) or device name
                        return action, tail.split()[0]
                    import re
                    clean = re.sub(r"[^a-zA-Z0-9_-]", "", tail.split()[0])
                    if clean:
                        return action, clean
                    return "error: app name required", None

                if action == "gui_key":
                    tail = _extract_tail(text, kw)
                    if tail:
                        return action, tail.split()[0]
                    return "error: key required", None

                if action == "gui_click":
                    import re
                    match = re.search(r"(\d{1,5})\s*[,\s]\s*(\d{1,5})", text_lower)
                    if match:
                        return action, f"{match.group(1)},{match.group(2)}"
                    return action, "current"

    return "unknown", None


def build_payload(action: str, args: str | None = None) -> bytes:
    """Build signed JSON payload for the daemon."""
    timestamp = int(time.time())
    nonce = os.urandom(16).hex()

    body = {
        "action": action,
        "args": args,
        "timestamp": timestamp,
        "nonce": nonce,
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def sign_payload(payload_bytes: bytes, hmac_secret: str) -> str:
    """Compute HMAC-SHA256 signature."""
    return hmac.new(
        hmac_secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


def send_command(
    action: str,
    tunnel_url: str,
    api_key: str,
    hmac_secret: str,
    args: str | None = None,
) -> dict:
    """
    Send a signed command to the local daemon via the HTTPS tunnel.
    Returns the daemon's JSON response as a dict.
    """
    payload = build_payload(action, args)
    signature = sign_payload(payload, hmac_secret)

    url = tunnel_url.rstrip("/") + "/command"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Mina-Signature": signature,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        # Try to parse the daemon's JSON error response and merge it
        try:
            err_data = json.loads(body)
            if isinstance(err_data, dict) and "error" in err_data:
                err_data["http_status"] = e.code
                return err_data
        except (json.JSONDecodeError, ValueError):
            pass
        return {"ok": False, "error": f"HTTP {e.code}", "detail": body}
    except urllib.error.URLError as e:
        return {"ok": False, "error": "connection_failed", "detail": str(e.reason)}
    except Exception as e:
        return {"ok": False, "error": "unexpected", "detail": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Mina Command Sender")
    parser.add_argument(
        "--nl", type=str,
        help="Natural language command (e.g. 'matikan PC', 'lock screen')",
    )
    parser.add_argument("--action", type=str, help="Direct action name")
    parser.add_argument("--args", type=str, help="Action argument (script name, volume level)")
    parser.add_argument("--tunnel-url", type=str, default=os.environ.get("MINA_TUNNEL_URL", ""))
    parser.add_argument("--api-key", type=str, default=os.environ.get("MINA_API_KEY", ""))
    parser.add_argument("--hmac-secret", type=str, default=os.environ.get("MINA_HMAC_SECRET", ""))
    args_cli = parser.parse_args()

    if not args_cli.tunnel_url or not args_cli.api_key or not args_cli.hmac_secret:
        print("Error: MINA_TUNNEL_URL, MINA_API_KEY, and MINA_HMAC_SECRET required.")
        print("Set as env vars or pass via --tunnel-url, --api-key, --hmac-secret")
        sys.exit(1)

    # Determine action from NL or direct
    action = args_cli.action
    action_args = args_cli.args

    if args_cli.nl and not action:
        action, action_args = parse_natural_language(args_cli.nl)
        if action.startswith("error"):
            print(f"Parse error: {action}")
            sys.exit(1)
        if action == "unknown":
            print(f"Could not parse: '{args_cli.nl}'")
            sys.exit(1)

    if not action:
        print("Error: provide --action or --nl")
        sys.exit(1)

    print(f"Sending: action={action}, args={action_args or 'none'}")
    result = send_command(
        action=action,
        tunnel_url=args_cli.tunnel_url,
        api_key=args_cli.api_key,
        hmac_secret=args_cli.hmac_secret,
        args=action_args,
    )
    print(f"Response: {json.dumps(result, indent=2)}")
    sys.exit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
