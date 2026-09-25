#!/usr/bin/env python3
"""Quick health check — verify the daemon is reachable through the tunnel."""
import sys
import urllib.request
import json
import os

url = os.environ.get("MINA_TUNNEL_URL", "")
if not url:
    print("Set MINA_TUNNEL_URL env var")
    sys.exit(1)

try:
    resp = urllib.request.urlopen(url.rstrip("/") + "/health", timeout=10)
    data = json.loads(resp.read())
    print("✓ Daemon is reachable!")
    print(f"  Service:  {data.get('service')}")
    print(f"  Platform: {data.get('platform')}")
    print(f"  Hostname: {data.get('hostname')}")
    print(f"  Version:  {data.get('version')}")
except Exception as e:
    print(f"✗ Connection failed: {e}")
    sys.exit(1)
