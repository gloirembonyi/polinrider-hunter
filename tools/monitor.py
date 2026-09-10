#!/usr/bin/env python3
"""Live monitor for polinrider-hunter.

    Prefer `polinrider-hunter monitor` unless you have this repo checked out.
    The same dashboard is built into the binary, works from any directory on
    any machine that ran the install command, and needs no Python at all. This
    script must be run from the directory it lives in.

    python monitor.py            live terminal dashboard
    python monitor.py --once     one snapshot, then exit (for scripts)
    python monitor.py --json     the same snapshot as JSON
    python monitor.py --web      local web dashboard on http://127.0.0.1:8787

The guard writes plain text to a state directory; this reads it and shows what
is going on. It is strictly a reader — it never edits config, never heals
anything, never stops the guard. That matters: a monitor you are not sure is
read-only is a monitor you hesitate to run.

Standard library only, Python 3.8+, no pip install. The same reason the Rust
side has no dependencies applies here: a tool about supply-chain compromise
should not ask you to trust a dependency tree to look at its own logs.
"""

# POLINRIDER-HUNTER-DETECTOR: this file names malware indicators. Not malware.

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Where the guard keeps its state — mirrors config::home() in the Rust source
# ---------------------------------------------------------------------------

def state_home() -> Path:
    override = os.environ.get("POLINRIDER_HOME")
    if override:
        return Path(override)
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "polinrider-hunter"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "polinrider-hunter"
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or "."
    return Path(home) / ".local" / "share" / "polinrider-hunter"


HOME = state_home()
CONFIG = HOME / "config.txt"
LOG = HOME / "hunter.log"
HEARTBEAT = HOME / "daemon.heartbeat"
QUARANTINE = HOME / "quarantine"
QINDEX = QUARANTINE / "index.jsonl"


# ---------------------------------------------------------------------------
# Reading the guard's state
# ---------------------------------------------------------------------------

def read_config() -> dict:
    cfg = {
        "paths": [],
        "interval": 30,
        "full_interval": 900,
        "git_interval": 3600,
        "auto_heal": True,
        "kill_procs": True,
        "notify": True,
    }
    try:
        text = CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return cfg
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "path":
            if value:
                cfg["paths"].append(value)
        elif key in ("interval", "full_interval", "git_interval"):
            try:
                cfg[key] = int(value)
            except ValueError:
                pass
        elif key in ("auto_heal", "kill_procs", "notify"):
            cfg[key] = value.lower() in ("1", "true", "yes", "on")
    return cfg


def read_heartbeat() -> tuple[int | None, float | None]:
    """(pid, age in seconds). The guard rewrites this every cycle."""
    try:
        parts = HEARTBEAT.read_text(encoding="utf-8").split()
        return int(parts[0]), time.time() - int(parts[1])
    except (OSError, ValueError, IndexError):
        return None, None


def pid_alive(pid: int) -> bool:
    """A fresh heartbeat from a dead process would be a lie worth catching."""
    if IS_WINDOWS:
        out = run(["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"])
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def process_stats(pid: int) -> dict:
    """Resident memory (MB) and CPU seconds, without a dependency."""
    if IS_WINDOWS:
        out = run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
            f"if ($p) {{ '{{0}}|{{1}}|{{2}}' -f $p.WorkingSet64, $p.CPU, $p.PriorityClass }}",
        ])
        parts = out.strip().split("|")
        if len(parts) == 3:
            try:
                return {
                    "memory_mb": round(int(parts[0]) / (1024 * 1024), 1),
                    "cpu_seconds": round(float(parts[1] or 0), 1),
                    "priority": parts[2],
                }
            except ValueError:
                pass
        return {}
    out = run(["ps", "-o", "rss=,time=", "-p", str(pid)])
    fields = out.split()
    if len(fields) >= 2:
        try:
            return {"memory_mb": round(int(fields[0]) / 1024, 1), "cpu_time": fields[1]}
        except ValueError:
            pass
    return {}


def run(cmd: list[str]) -> str:
    """Run a helper, headless, and never raise."""
    kwargs = {}
    if IS_WINDOWS:
        # Otherwise every poll flashes a console window — the exact bug the
        # Rust side had to fix.
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs["startupinfo"] = si
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, **kwargs
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# ---------------------------------------------------------------------------
# The log
# ---------------------------------------------------------------------------

LOG_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})Z\s+(.*)$")
DETECT = re.compile(r"^DETECT (.+?) \[(.*?)\] -> (.*)$")
NOTICE = re.compile(r"^NOTICE (.+?) \[(.*?)\]$")
PROC = re.compile(r"^PROC pid=(\d+) marker=(\S+)(?: -> (.*))?$")
REF = re.compile(r"^REF (.+?) (\S+) :: (.+?) \[(.*?)\]$")
STARTED = re.compile(r"^guard started: (\d+) path")


def read_events(limit: int = 400) -> list[dict]:
    """Parse the log tail into structured events, newest last."""
    try:
        # Read only the tail: this file grows for the life of the install.
        size = LOG.stat().st_size
        with LOG.open("rb") as fh:
            if size > 256 * 1024:
                fh.seek(size - 256 * 1024)
                fh.readline()  # discard the partial first line
            raw = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []

    events = []
    for line in raw.splitlines():
        m = LOG_LINE.match(line.strip())
        if not m:
            continue
        when, body = m.group(1), m.group(2)
        ev = {"time": when, "kind": "info", "text": body}

        d = DETECT.match(body)
        n = NOTICE.match(body)
        p = PROC.match(body)
        r = REF.match(body)
        if d:
            ev.update(kind="detect", path=d.group(1),
                      iocs=[i for i in d.group(2).split(",") if i],
                      outcome=d.group(3))
            ev["ok"] = ("healed" in ev["outcome"]) or ("deleted" in ev["outcome"])
        elif n:
            ev.update(kind="notice", path=n.group(1),
                      iocs=[i for i in n.group(2).split(",") if i])
        elif p:
            ev.update(kind="process", pid=int(p.group(1)), marker=p.group(2),
                      outcome=(p.group(3) or ""))
        elif r:
            ev.update(kind="ref", repo=r.group(1), ref=r.group(2), file=r.group(3),
                      iocs=[i for i in r.group(4).split(",") if i])
        elif STARTED.match(body):
            ev["kind"] = "started"
        events.append(ev)
    return events[-limit:]


def read_quarantine() -> list[dict]:
    try:
        lines = QINDEX.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ---------------------------------------------------------------------------
# The snapshot everything else renders
# ---------------------------------------------------------------------------

def snapshot() -> dict:
    cfg = read_config()
    pid, age = read_heartbeat()
    alive = bool(pid and age is not None
                 and age <= max(cfg["interval"] * 3, 90)
                 and pid_alive(pid))
    events = read_events()
    quarantine = read_quarantine()

    detections = [e for e in events if e["kind"] == "detect"]
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "home": str(HOME),
        "guard": {
            "running": alive,
            "pid": pid,
            "heartbeat_age": round(age, 1) if age is not None else None,
            "stats": process_stats(pid) if (alive and pid) else {},
        },
        "config": cfg,
        "counts": {
            "detections": len(detections),
            "cleaned": sum(1 for e in detections if e.get("ok")),
            "needs_review": sum(1 for e in detections if not e.get("ok"))
                            + sum(1 for e in events if e["kind"] == "notice"),
            "processes_stopped": sum(1 for e in events
                                     if e["kind"] == "process" and "killed" in e.get("outcome", "")),
            "infected_refs": sum(1 for e in events if e["kind"] == "ref"),
            "quarantined": len(quarantine),
        },
        "events": events[-40:],
        "quarantine": quarantine[-20:],
    }


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------

class C:
    def __init__(self, on: bool):
        self.on = on

    def __call__(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text


def use_colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if IS_WINDOWS:
        # Enable VT processing; on anything modern this already works.
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


def human_age(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    s = int(seconds)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def render_terminal(snap: dict, c: C) -> str:
    width = min(shutil.get_terminal_size((100, 30)).columns, 110)
    out = []
    rule = "─" * width

    g = snap["guard"]
    if g["running"]:
        badge = c("32", "● RUNNING")
        detail = f"pid {g['pid']}, beat {human_age(g['heartbeat_age'])}"
        st = g.get("stats") or {}
        if st.get("memory_mb") is not None:
            detail += f", {st['memory_mb']} MB"
        if st.get("priority"):
            detail += f", {st['priority']}"
    else:
        badge = c("31", "● NOT RUNNING")
        detail = "start it with: polinrider-hunter install"

    out.append(c("1", "polinrider-hunter") + c("2", "  monitor"))
    out.append(rule)
    out.append(f"  guard      {badge}  {c('2', detail)}")

    cfg = snap["config"]
    out.append("  cadence    " + c("2",
        f"quick {cfg['interval']}s / full {cfg['full_interval']}s / git {cfg['git_interval']}s"))
    flags = []
    flags.append(("auto-heal " + ("on" if cfg["auto_heal"] else "OFF")))
    flags.append(("notify " + ("on" if cfg["notify"] else "OFF")))
    flags.append(("stop-processes " + ("on" if cfg["kill_procs"] else "OFF")))
    out.append("  settings   " + c("2", " · ".join(flags)))
    out.append(f"  watching   {c('2', str(len(cfg['paths'])) + ' path(s)')}")
    for p in cfg["paths"][:8]:
        out.append(c("2", f"               {p}"))
    if len(cfg["paths"]) > 8:
        out.append(c("2", f"               … and {len(cfg['paths']) - 8} more"))

    n = snap["counts"]
    out.append("")
    out.append("  " + "   ".join([
        c("32", f"{n['cleaned']} cleaned"),
        c("33", f"{n['needs_review']} need review"),
        c("31", f"{n['processes_stopped']} processes stopped"),
        c("2", f"{n['quarantined']} quarantined"),
    ]))
    out.append(rule)

    events = [e for e in snap["events"] if e["kind"] in ("detect", "notice", "process", "ref")]
    out.append(c("1", "  Recent activity"))
    if not events:
        out.append(c("2", "    nothing yet — the log is quiet, which is the good outcome"))
    for e in events[-14:]:
        when = c("2", e["time"][5:16])
        if e["kind"] == "detect":
            tag = c("32", "CLEANED ") if e.get("ok") else c("31", "FAILED  ")
            what = shorten(e.get("path", ""), width - 34)
            out.append(f"    {when}  {tag} {what}")
            if e.get("iocs"):
                out.append(c("2", f"                        {', '.join(e['iocs'][:5])}"))
        elif e["kind"] == "notice":
            out.append(f"    {when}  {c('33', 'REVIEW  ')} {shorten(e.get('path', ''), width - 34)}")
        elif e["kind"] == "process":
            out.append(f"    {when}  {c('31', 'PROCESS ')} pid {e.get('pid')} "
                       f"{c('2', e.get('marker', ''))} {e.get('outcome', '')}")
        elif e["kind"] == "ref":
            out.append(f"    {when}  {c('35', 'BRANCH  ')} "
                       f"{e.get('ref', '')} :: {shorten(e.get('file', ''), 40)}")

    out.append(rule)
    out.append(c("2", f"  state: {snap['home']}"))
    out.append(c("2", f"  {snap['generated']}"))
    return "\n".join(out)


def shorten(path: str, limit: int) -> str:
    if limit < 20 or len(path) <= limit:
        return path
    return "…" + path[-(limit - 1):]


# ---------------------------------------------------------------------------
# Web dashboard
# ---------------------------------------------------------------------------

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>polinrider-hunter monitor</title>
<style>
:root{--bg:#05060f;--panel:rgba(255,255,255,.035);--line:rgba(255,255,255,.08);
--text:#f4f5fb;--muted:rgba(244,245,251,.45);--accent:#818cf8;--ok:#4ade80;
--warn:#fbbf24;--bad:#f87171;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);background-image:radial-gradient(circle at 50% 110%,#191645 0%,#05060f 55%,#010104 100%);
background-attachment:fixed;color:var(--text);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}
.wrap{max-width:1000px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:1.4rem;margin:0 0 4px;font-weight:700}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:24px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:16px}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;gap:7px;font-size:.72rem;font-weight:700;
text-transform:uppercase;letter-spacing:.07em;padding:5px 12px;border-radius:999px;border:1px solid var(--line)}
.ok{color:var(--ok);border-color:rgba(74,222,128,.35);background:rgba(74,222,128,.12)}
.bad{color:var(--bad);border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.12)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-top:6px}
.stat b{display:block;font-size:1.9rem;font-weight:400;line-height:1.1}
.stat span{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:.86rem}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
.t{color:var(--muted);white-space:nowrap;font-family:var(--mono);font-size:.78rem}
.tag{font-size:.65rem;font-weight:800;letter-spacing:.06em;padding:2px 8px;border-radius:999px;white-space:nowrap}
.tag.c{color:var(--ok);background:rgba(74,222,128,.12)}
.tag.r{color:var(--warn);background:rgba(251,191,36,.12)}
.tag.p{color:var(--bad);background:rgba(248,113,113,.12)}
.tag.b{color:var(--accent);background:rgba(129,140,248,.12)}
code{font-family:var(--mono);font-size:.82em;color:var(--muted);word-break:break-all}
.muted{color:var(--muted)}.empty{color:var(--muted);padding:10px}
h2{font-size:.72rem;text-transform:uppercase;letter-spacing:.13em;color:var(--muted);margin:0 0 12px;font-weight:800}
</style></head><body><div class="wrap" id="app">loading…</div>
<script>
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function age(s){if(s==null)return'never';s=Math.floor(s);
 return s<60?s+'s ago':s<3600?Math.floor(s/60)+'m ago':Math.floor(s/3600)+'h ago'}
function render(d){
 const g=d.guard,c=d.counts,cf=d.config;
 const st=g.stats||{};
 let bits=[];if(g.pid)bits.push('pid '+g.pid);
 if(g.heartbeat_age!=null)bits.push('beat '+age(g.heartbeat_age));
 if(st.memory_mb!=null)bits.push(st.memory_mb+' MB');
 if(st.priority)bits.push(st.priority);
 const rows=(d.events||[]).slice().reverse().filter(e=>e.kind!=='info'&&e.kind!=='started');
 document.getElementById('app').innerHTML=`
 <h1>polinrider-hunter</h1><div class="sub">monitor · ${esc(d.generated)}</div>
 <div class="panel">
  <div class="row"><span class="badge ${g.running?'ok':'bad'}">${g.running?'● guard running':'● guard not running'}</span>
  <span class="muted">${esc(bits.join(' · '))}</span></div>
  <div class="grid" style="margin-top:18px">
   <div class="stat"><b>${c.cleaned}</b><span>cleaned</span></div>
   <div class="stat"><b>${c.needs_review}</b><span>need review</span></div>
   <div class="stat"><b>${c.processes_stopped}</b><span>processes stopped</span></div>
   <div class="stat"><b>${c.quarantined}</b><span>quarantined</span></div>
  </div>
 </div>
 <div class="panel"><h2>Configuration</h2>
  <div class="muted" style="font-size:.86rem">
   quick ${cf.interval}s · full ${cf.full_interval}s · git ${cf.git_interval}s<br>
   auto-heal ${cf.auto_heal?'on':'OFF'} · notify ${cf.notify?'on':'OFF'} · stop-processes ${cf.kill_procs?'on':'OFF'}
  </div>
  <div style="margin-top:12px">${(cf.paths||[]).map(p=>`<div><code>${esc(p)}</code></div>`).join('')||'<span class="empty">no paths configured</span>'}</div>
 </div>
 <div class="panel"><h2>Recent activity</h2>
  ${rows.length?`<table>${rows.map(e=>{
    let tag='',what='';
    if(e.kind==='detect'){tag=e.ok?'<span class="tag c">cleaned</span>':'<span class="tag p">failed</span>';
      what=`<code>${esc(e.path)}</code><br><span class="muted" style="font-size:.78rem">${esc((e.iocs||[]).join(', '))}</span>`}
    else if(e.kind==='notice'){tag='<span class="tag r">review</span>';what=`<code>${esc(e.path)}</code>`}
    else if(e.kind==='process'){tag='<span class="tag p">process</span>';what=`pid ${esc(e.pid)} <span class="muted">${esc(e.marker)}</span> ${esc(e.outcome)}`}
    else if(e.kind==='ref'){tag='<span class="tag b">branch</span>';what=`${esc(e.ref)} :: <code>${esc(e.file)}</code>`}
    return `<tr><td class="t">${esc(e.time)}</td><td>${tag}</td><td>${what}</td></tr>`}).join('')}</table>`
   :'<div class="empty">Nothing yet — a quiet log is the good outcome.</div>'}
 </div>
 <div class="panel"><h2>Quarantine</h2>
  ${(d.quarantine||[]).length?`<table>${d.quarantine.slice().reverse().map(q=>
    `<tr><td class="t">${esc(q.time)}</td><td><code>${esc(q.original)}</code><br>
     <span class="muted" style="font-size:.78rem">${esc((q.iocs||[]).join(', '))}</span></td></tr>`).join('')}</table>`
   :'<div class="empty">Empty — nothing has been removed from your files.</div>'}
 </div>
 <div class="sub">state: <code>${esc(d.home)}</code> · refreshes every 5s · read-only</div>`}
function tick(){fetch('api/state',{cache:'no-store'}).then(r=>r.json()).then(render)
 .catch(()=>{document.getElementById('app').innerHTML='<h1>monitor</h1><p class="sub">lost contact with the monitor process.</p>'})}
tick();setInterval(tick,5000);
</script></body></html>"""


def serve(port: int) -> int:
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/").endswith("api/state"):
                body = json.dumps(snapshot(), indent=1).encode()
                ctype = "application/json"
            elif self.path in ("/", "/index.html"):
                body = PAGE.encode()
                ctype = "text/html; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass  # a dashboard that spams the terminal it runs in is no use

    # 127.0.0.1, never 0.0.0.0: this exposes where your infections were found,
    # and has no business being reachable from the network.
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"monitor on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    print("bound to localhost only — it is not reachable from the network")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Live monitor for polinrider-hunter (read-only).")
    ap.add_argument("--once", action="store_true", help="one snapshot, then exit")
    ap.add_argument("--json", action="store_true", help="emit the snapshot as JSON")
    ap.add_argument("--web", action="store_true", help="serve a local web dashboard")
    ap.add_argument("--port", type=int, default=8787, help="port for --web (default 8787)")
    ap.add_argument("--interval", type=float, default=3.0,
                    help="terminal refresh seconds (default 3)")
    args = ap.parse_args()

    if not HOME.exists():
        print(f"No polinrider-hunter state at {HOME}", file=sys.stderr)
        print("Install it first, or set POLINRIDER_HOME.", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(snapshot(), indent=2))
        return 0
    if args.web:
        return serve(args.port)

    c = C(use_colour())
    if args.once:
        print(render_terminal(snapshot(), c))
        return 0

    try:
        while True:
            frame = render_terminal(snapshot(), c)
            # Home the cursor and clear forward, rather than clearing the whole
            # screen: no flicker, and scrollback survives.
            sys.stdout.write("\033[H\033[J" if c.on else "\n" * 2)
            sys.stdout.write(frame + "\n")
            sys.stdout.write(c("2", "  Ctrl+C to stop") + "\n")
            sys.stdout.flush()
            time.sleep(max(args.interval, 0.5))
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
