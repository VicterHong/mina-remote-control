#!/usr/bin/env python3
"""
Mina Dashboard — generate an HTML monitoring dashboard and (optionally)
open it full-screen in the browser.

Data sources (best-effort, stdlib + psutil if present):
  - CPU / memory / disk / uptime (psutil or /proc fallbacks)
  - Docker container status (docker ps, if available)
  - Mina daemon state (its own log tail)

Usage:
    python3 dashboard.py --out ~/.mina/dashboard.html   # just generate
    python3 dashboard.py --open                         # generate + open browser
    python3 dashboard.py --open --interval 30           # auto-refresh every 30s
"""
from __future__ import annotations

import argparse
import html
import json
import platform
import shutil
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from gui_automation import open_url_cmd, get_platform
except ImportError:  # running from another cwd
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from gui_automation import open_url_cmd, get_platform

MINA_LOG = Path.home() / ".mina" / "logs" / "mina_daemon.log"


def collect_metrics() -> dict:
    """Collect system metrics with graceful degradation."""
    m = {
        "hostname": platform.node(),
        "platform": get_platform(),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if HAS_PSUTIL:
        m["cpu_percent"] = psutil.cpu_percent(interval=0.5)
        vm = psutil.virtual_memory()
        m["mem_percent"] = vm.percent
        m["mem_used_gb"] = round(vm.used / 1024**3, 1)
        m["mem_total_gb"] = round(vm.total / 1024**3, 1)
        try:
            du = psutil.disk_usage("/")
            m["disk_percent"] = du.percent
            m["disk_used_gb"] = round(du.used / 1024**3, 1)
            m["disk_total_gb"] = round(du.total / 1024**3, 1)
        except Exception:
            pass
        m["uptime_h"] = round((time.time() - psutil.boot_time()) / 3600, 1)
    else:
        # /proc fallbacks (Linux)
        try:
            with open("/proc/loadavg") as f:
                m["loadavg"] = f.read().split()[:3]
            with open("/proc/uptime") as f:
                m["uptime_h"] = round(float(f.read().split()[0]) / 3600, 1)
        except Exception:
            pass
    return m


def collect_containers() -> list[dict]:
    """List running containers (docker CLI, best-effort)."""
    if not shutil.which("docker"):
        return []
    try:
        r = subprocess.run(
            ["docker", "ps", "--format",
             "{{.Names}}\t{{.Status}}\t{{.Image}}"],
            capture_output=True, text=True, timeout=10, shell=False,
        )
        if r.returncode != 0:
            return []
        out = []
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                out.append({"name": parts[0], "status": parts[1],
                            "image": parts[2]})
        return out
    except Exception:
        return []


def tail_mina_log(n: int = 12) -> list[str]:
    """Read the last n log lines without loading the whole file (low RAM)."""
    if not MINA_LOG.exists():
        return []
    try:
        with open(MINA_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 8192)  # read at most the last 8 KB
            f.seek(size - chunk)
            data = f.read().decode("utf-8", errors="replace")
        return data.splitlines()[-n:]
    except Exception:
        return []


def _bar(pct: float, color: str) -> str:
    pct = max(0.0, min(100.0, float(pct or 0)))
    return (
        f'<div class="bar"><div class="fill" style="width:{pct:.1f}%;'
        f'background:{color}"></div></div><span class="pct">{pct:.0f}%</span>'
    )


def render_html(m: dict, containers: list[dict], loglines: list[str],
                interval: int | None) -> str:
    refresh = (f'<meta http-equiv="refresh" content="{interval}">'
               if interval else "")
    esc = html.escape

    cards = []
    if "cpu_percent" in m:
        color = "#e74c3c" if m["cpu_percent"] > 80 else "#2ecc71"
        cards.append(f'<div class="card"><h3>CPU</h3>'
                     f'{_bar(m["cpu_percent"], color)}</div>')
    if "mem_percent" in m:
        color = "#e74c3c" if m["mem_percent"] > 90 else "#3498db"
        cards.append(
            f'<div class="card"><h3>Memory</h3>'
            f'{_bar(m["mem_percent"], color)}'
            f'<p>{m.get("mem_used_gb","?")} / {m.get("mem_total_gb","?")} GB</p></div>')
    if "disk_percent" in m:
        color = "#e67e22" if m["disk_percent"] > 85 else "#9b59b6"
        cards.append(
            f'<div class="card"><h3>Disk /</h3>'
            f'{_bar(m["disk_percent"], color)}'
            f'<p>{m.get("disk_used_gb","?")} / {m.get("disk_total_gb","?")} GB</p></div>')
    if "uptime_h" in m:
        up = timedelta(hours=m["uptime_h"])
        cards.append(f'<div class="card"><h3>Uptime</h3>'
                     f'<p class="big">{str(up).split(".")[0]}</p></div>')

    rows = "".join(
        f'<tr><td>{esc(c["name"])}</td><td>{esc(c["status"])}</td>'
        f'<td>{esc(c["image"])}</td></tr>' for c in containers
    ) or '<tr><td colspan="3" class="muted">No containers detected</td></tr>'

    log_html = "<br>".join(esc(l) for l in loglines) or \
        '<span class="muted">No daemon log yet</span>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">{refresh}
<title>MINA Dashboard — {esc(m['hostname'])}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
         background:#0d1117; color:#e6edf3; margin:0; padding:24px; }}
  h1 {{ font-size:1.3rem; margin:0 0 4px; }}
  .sub {{ color:#8b949e; font-size:.85rem; margin-bottom:20px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
          gap:16px; margin-bottom:24px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:10px;
          padding:16px; }}
  .card h3 {{ margin:0 0 10px; font-size:.8rem; text-transform:uppercase;
             letter-spacing:.08em; color:#8b949e; }}
  .bar {{ background:#21262d; border-radius:6px; height:14px; overflow:hidden;
         display:inline-block; width:75%; vertical-align:middle; }}
  .fill {{ height:100%; transition:width .4s; }}
  .pct {{ margin-left:8px; font-size:.85rem; }}
  .big {{ font-size:1.6rem; margin:6px 0 0; }}
  p {{ margin:8px 0 0; font-size:.85rem; color:#8b949e; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #21262d; }}
  th {{ color:#8b949e; font-weight:600; }}
  .muted {{ color:#484f58; }}
  pre {{ background:#161b22; border:1px solid #30363d; border-radius:10px;
        padding:14px; font-size:.78rem; overflow-x:auto; line-height:1.5; }}
  section {{ margin-bottom:24px; }}
  h2 {{ font-size:.95rem; color:#8b949e; text-transform:uppercase;
       letter-spacing:.08em; }}
</style></head><body>
<h1>⚡ MINA — {esc(m['hostname'])}</h1>
<div class="sub">{esc(m['platform'])} · generated {esc(m['generated_at'])}
{' · auto-refresh ' + str(interval) + 's' if interval else ''}</div>
<div class="grid">{''.join(cards)}</div>
<section><h2>Containers</h2>
<table><tr><th>Name</th><th>Status</th><th>Image</th></tr>{rows}</table>
</section>
<section><h2>Mina daemon log (tail)</h2><pre>{log_html}</pre></section>
</body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Mina monitoring dashboard")
    parser.add_argument("--out", type=str,
                        default=str(Path.home() / ".mina" / "dashboard.html"))
    parser.add_argument("--open", action="store_true",
                        help="Open the dashboard in the default browser")
    parser.add_argument("--interval", type=int, default=None,
                        help="Auto-refresh interval in seconds (embedded in HTML)")
    args = parser.parse_args()

    m = collect_metrics()
    containers = collect_containers()
    loglines = tail_mina_log()
    doc = render_html(m, containers, loglines, args.interval)

    out = Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc)

    print(json.dumps({"ok": True, "dashboard": str(out),
                      "bytes": len(doc),
                      "containers": len(containers),
                      "psutil": HAS_PSUTIL}, indent=2))

    if args.open:
        cmd = open_url_cmd(out.as_uri())
        if not cmd:
            print("✗ cannot build launcher for this platform")
            return
        try:
            subprocess.Popen(cmd, shell=False,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            print(f"✓ opened {out.as_uri()}")
        except Exception as e:
            print(f"✗ failed to open: {e}")


if __name__ == "__main__":
    main()
