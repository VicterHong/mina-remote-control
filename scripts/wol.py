#!/usr/bin/env python3
"""
Mina Wake-on-LAN — send magic packets to wake LAN devices (stdlib only).

WoL sends a "magic packet" (6x 0xFF + 16x target MAC) via UDP broadcast.
The target NIC must have WoL enabled (BIOS/UEFI + OS). A sleeping machine
cannot receive commands over the tunnel, so waking THE laptop requires a
relay on the same LAN — this script is that relay primitive:

  - run it from another always-on device on the LAN (Raspberry Pi, router,
    second laptop running the Mina daemon), OR
  - call it through the daemon's `wake` action to wake OTHER LAN devices.

Usage:
    python3 wol.py --device nas               # named device from commands.yaml
    python3 wol.py --mac AA:BB:CC:DD:EE:FF    # raw MAC (broadcast 255.255.255.255)
    python3 wol.py --mac AA:BB:.. --broadcast 192.168.1.255 --port 9

Exit codes: 0 sent; 1 invalid input / device not found.
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

DEFAULT_BROADCAST = "255.255.255.255"
DEFAULT_PORT = 9


def normalize_mac(mac: str) -> str:
    """Return lowercase colon-separated MAC."""
    return mac.replace("-", ":").lower()


def build_magic_packet(mac: str) -> bytes:
    """Build the 102-byte WoL magic packet for a MAC address."""
    if not MAC_RE.match(mac):
        raise ValueError(f"invalid MAC address: {mac!r}")
    mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    return b"\xff" * 6 + mac_bytes * 16


def send_magic_packet(
    mac: str,
    broadcast: str = DEFAULT_BROADCAST,
    port: int = DEFAULT_PORT,
) -> dict:
    """Send a magic packet to (broadcast, port). Returns a result dict."""
    try:
        packet = build_magic_packet(mac)
    except ValueError as e:
        return {"ok": False, "error": "invalid_mac", "detail": str(e)}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(packet, (broadcast, port))
    except OSError as e:
        return {"ok": False, "error": "send_failed", "detail": str(e)}

    return {
        "ok": True,
        "mac": normalize_mac(mac),
        "broadcast": broadcast,
        "port": port,
        "bytes": len(packet),
    }


# ── Device registry (commands.yaml -> devices:) ──────────────────

def _config_candidates() -> list[Path]:
    return [
        Path.home() / ".mina" / "devices.yaml",
        Path(__file__).resolve().parent.parent / "config" / "commands.yaml",
        Path.home() / ".hermes" / "skills" / "system-control"
        / "mina-workspace" / "config" / "commands.yaml",
    ]


def load_devices() -> dict:
    """Load {name: {mac, broadcast?, port?}} from the first config found."""
    if not HAS_YAML:
        return {}
    for path in _config_candidates():
        if not path.exists():
            continue
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            continue
        devices = data.get("devices")
        if isinstance(devices, dict):
            return devices
    return {}


def wake_device(name: str) -> dict:
    """Wake a named device from the registry."""
    devices = load_devices()
    spec = devices.get(name)
    if not spec:
        return {
            "ok": False,
            "error": "unknown_device",
            "detail": f"'{name}' not in devices registry "
                      f"(known: {', '.join(sorted(devices)) or 'none'})",
        }
    if not isinstance(spec, dict) or "mac" not in spec:
        return {"ok": False, "error": "invalid_device_spec",
                "detail": f"device '{name}' has no 'mac' field"}
    return send_magic_packet(
        spec["mac"],
        spec.get("broadcast", DEFAULT_BROADCAST),
        int(spec.get("port", DEFAULT_PORT)),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Mina Wake-on-LAN sender")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--device", type=str, help="Named device from registry")
    group.add_argument("--mac", type=str, help="Target MAC (AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--broadcast", type=str, default=DEFAULT_BROADCAST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--list", action="store_true",
                        help="List known devices and exit")
    args = parser.parse_args()

    if args.list:
        devices = load_devices()
        if not devices:
            print("No devices registered. Add a 'devices:' section to "
                  "commands.yaml or create ~/.mina/devices.yaml")
            sys.exit(0)
        for name, spec in sorted(devices.items()):
            mac = spec.get("mac", "?") if isinstance(spec, dict) else "?"
            print(f"  {name:<20} {mac}")
        sys.exit(0)

    if args.device:
        result = wake_device(args.device)
    else:
        result = send_magic_packet(args.mac, args.broadcast, args.port)

    if result.get("ok"):
        print(f"✓ Magic packet sent to {result['mac']} "
              f"via {result['broadcast']}:{result['port']} "
              f"({result['bytes']} bytes)")
        sys.exit(0)
    print(f"✗ {result.get('error')}: {result.get('detail')}")
    sys.exit(1)


if __name__ == "__main__":
    main()
