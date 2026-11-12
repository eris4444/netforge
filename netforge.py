#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetForge - Terminal network toolkit
  * Multi SSH-proxy (tunnel) server manager: any number, any port, any user/pass
  * Per-interface inspection, live traffic graphs, packet capture & analysis
  * IP / link management, MAC changer with full restore
  * Wireless monitor mode with complete state backup & restore
  * Network utilities (public IP, ping, trace, DNS, ports, LAN discovery, wifi scan)
"""

import argparse
import datetime as dt
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, deque

try:
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("NetForge needs the 'rich' library:  sudo apt install python3-rich")
    sys.exit(1)

VERSION = "1.2.1"
STATE_DIR = "/var/lib/netforge"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
CAPTURE_DIR = os.path.join(STATE_DIR, "captures")
SSH_CONF_DIR = "/etc/netforge/ssh"
UNIT_FILE = "/etc/systemd/system/netforge-sshd@.service"
DENY_DROPIN = "/etc/ssh/sshd_config.d/99-netforge.conf"
PROXY_GROUP = "netforge"
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"

console = Console(highlight=False)

ACCENT = "bright_cyan"
ACCENT2 = "magenta"
OK = "bold green"
WARN = "bold yellow"
ERR = "bold red"
DIM = "grey50"


# ════════════════════════════════════════════════════════════════════
#  Generic helpers
# ════════════════════════════════════════════════════════════════════

def run(cmd, timeout=None, input_text=None):
    """Run a command (list). Returns (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return 124, out, "timeout"


def has(tool):
    return shutil.which(tool) is not None


def read_file(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def human_bytes(n, suffix="B"):
    n = float(n)
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(n) < 1024:
            return f"{n:6.1f} {unit}{suffix}" if unit else f"{n:6.0f} {suffix}"
        n /= 1024
    return f"{n:.1f} E{suffix}"


def human_rate(bps):
    return human_bytes(bps, "B/s")


def sparkline(values, width=40):
    blocks = "▁▂▃▄▅▆▇█"
    vals = list(values)[-width:]
    if not vals:
        return ""
    mx = max(vals) or 1
    return "".join(blocks[min(7, int(v / mx * 7))] if v > 0 else " " for v in vals).rjust(width)


def load_state():
    st = {}
    try:
        with open(STATE_FILE) as f:
            st = json.load(f)
    except (OSError, ValueError):
        pass
    st.setdefault("proxies", {})
    st.setdefault("monitor", {})
    st.setdefault("orig_mac", {})
    st.setdefault("tunnels", {})
    st.setdefault("obfs4", {})
    return st


def save_state(st):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f, indent=2)
    os.replace(tmp, STATE_FILE)


# ────────────────────────────── UI helpers ──────────────────────────

LETTERS = {
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "F": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "██║     ", "╚═╝     "],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "G": [" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
}


def gradient_banner(word="NETFORGE"):
    rows = ["".join(LETTERS[c][i] for c in word) for i in range(6)]
    width = max(len(r) for r in rows)
    start, end = (0, 220, 255), (200, 60, 255)
    text = Text()
    for r in rows:
        for x, ch in enumerate(r):
            t = x / max(1, width - 1)
            rgb = tuple(int(start[k] + (end[k] - start[k]) * t) for k in range(3))
            text.append(ch, style=f"bold #{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}")
        text.append("\n")
    return text, width


def header(subtitle=None):
    console.clear()
    banner, width = gradient_banner()
    if console.width >= width + 4:
        console.print(Align.center(banner))
    else:
        console.print(Align.center(Text("N E T F O R G E", style="bold bright_cyan")))
    st = load_state()
    tup = sum(1 for n, t in st["tunnels"].items() if tun_listening(t))
    up = sum(1 for i in list_ifaces() if read_file(f"/sys/class/net/{i}/operstate") == "up")
    info = Text.assemble(
        ("  ", ""), (f"v{VERSION}", "bold magenta"), ("  │  ", DIM),
        ("host ", DIM), (socket.gethostname(), "bold white"), ("  │  ", DIM),
        ("links up ", DIM), (str(up), "bold green"), ("  │  ", DIM),
        ("tunnels up ", DIM), (f"{tup}/{len(st['tunnels'])}", "bold cyan"), ("  │  ", DIM),
        ("monitor ", DIM), (str(len(st["monitor"])), "bold yellow" if st["monitor"] else "bold white"),
    )
    console.print(Align.center(info))
    if subtitle:
        console.print(Align.center(Text(f"━━━  {subtitle}  ━━━", style=f"bold {ACCENT2}")))
    console.print()


def menu(title, options, color=ACCENT, subtitle=None):
    """options: list of (key, label, description). Returns chosen key."""
    header(subtitle or title)
    t = Table(box=box.ROUNDED, border_style=color, show_header=False, padding=(0, 2), expand=False)
    t.add_column(justify="right", style=f"bold {color}")
    t.add_column(style="bold white")
    t.add_column(style=DIM)
    for key, label, desc in options:
        if key is None:
            t.add_row("", Text(label, style=f"bold {ACCENT2}"), "")
            continue
        t.add_row(Text(f"[{key}]", style=f"bold {color}"), label, desc)
    console.print(Align.center(Panel(t, title=f"[bold {color}]{title}[/]", border_style=color, padding=(1, 2))))
    keys = [k for k, _, _ in options if k is not None]
    while True:
        try:
            c = Prompt.ask(f"\n  [bold {color}]netforge[/] [white]›[/]").strip().lower()
        except EOFError:
            return "0"
        if c in keys:
            return c
        console.print(f"  [{ERR}]Invalid choice[/]")


def pause():
    try:
        Prompt.ask(f"\n  [{DIM}]Press Enter to continue[/]", default="", show_default=False)
    except EOFError:
        pass


def ok(msg):
    console.print(f"  [{OK}]✔[/] {msg}")


def warn(msg):
    console.print(f"  [{WARN}]![/] {msg}")


def err(msg):
    console.print(f"  [{ERR}]✘[/] {msg}")


def info(msg):
    console.print(f"  [{ACCENT}]➜[/] {msg}")


def ask(msg, default=None, password=False):
    if default is None:
        return Prompt.ask(f"  [bold cyan]?[/] {msg}", password=password).strip()
    return Prompt.ask(f"  [bold cyan]?[/] {msg}", default=str(default), password=password).strip()


def ask_int(msg, default=None, lo=None, hi=None):
    while True:
        v = IntPrompt.ask(f"  [bold cyan]?[/] {msg}", default=default)
        if (lo is None or v >= lo) and (hi is None or v <= hi):
            return v
        err(f"Value must be between {lo} and {hi}")


def confirm(msg, default=False):
    return Confirm.ask(f"  [bold yellow]?[/] {msg}", default=default)


def step(cmd, desc=None):
    """Run a command, print success/failure line. Returns True on success."""
    rc, out, e = run(cmd)
    label = desc or " ".join(cmd)
    if rc == 0:
        console.print(f"  [{OK}]✔[/] [white]{label}[/]")
        return True
    console.print(f"  [{ERR}]✘[/] [white]{label}[/] [{DIM}]{(e or out).strip()[:200]}[/]")
    return False


# ════════════════════════════════════════════════════════════════════
#  Interface information
# ════════════════════════════════════════════════════════════════════

def list_ifaces(include_lo=False):
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
    return [n for n in names if include_lo or n != "lo"]


def is_wireless(iface):
    return os.path.exists(f"/sys/class/net/{iface}/wireless") or os.path.exists(f"/sys/class/net/{iface}/phy80211")


def get_phy(iface):
    return read_file(f"/sys/class/net/{iface}/phy80211/name") or None


def iface_type(iface):
    if is_wireless(iface):
        return "wifi"
    if iface == "lo":
        return "loopback"
    if os.path.exists(f"/sys/class/net/{iface}/bridge"):
        return "bridge"
    if not os.path.exists(f"/sys/class/net/{iface}/device"):
        if iface.startswith(("tun", "tap", "wg")):
            return "tunnel"
        return "virtual"
    return "ethernet"


def get_driver(iface):
    p = f"/sys/class/net/{iface}/device/driver"
    return os.path.basename(os.readlink(p)) if os.path.islink(p) else "-"


def get_addrs(iface=None):
    """Returns {iface: [{'family','local','prefixlen','dynamic'}...]}"""
    cmd = ["ip", "-j", "addr", "show"] + (["dev", iface] if iface else [])
    rc, out, _ = run(cmd)
    res = {}
    try:
        for entry in json.loads(out or "[]"):
            lst = []
            for a in entry.get("addr_info", []):
                lst.append({"family": a.get("family"), "local": a.get("local"),
                            "prefixlen": a.get("prefixlen"), "dynamic": a.get("dynamic", False),
                            "scope": a.get("scope")})
            res[entry["ifname"]] = lst
    except (ValueError, KeyError):
        pass
    return res


def perm_mac(iface):
    rc, out, _ = run(["ethtool", "-P", iface])
    m = re.search(r"([0-9a-f]{2}(:[0-9a-f]{2}){5})", out.lower())
    if m and m.group(1) != "00:00:00:00:00:00":
        return m.group(1)
    return None


def iw_info(iface):
    d = {}
    if not is_wireless(iface) or not has("iw"):
        return d
    rc, out, _ = run(["iw", "dev", iface, "info"])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("type "):
            d["mode"] = line.split(None, 1)[1]
        elif line.startswith("ssid "):
            d["ssid"] = line.split(None, 1)[1]
        elif line.startswith("channel "):
            d["channel"] = line.split(",")[0].replace("channel ", "")
        elif line.startswith("txpower "):
            d["txpower"] = line.split(None, 1)[1]
    rc, out, _ = run(["iw", "dev", iface, "link"])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("signal:"):
            d["signal"] = line.split(":", 1)[1].strip()
        elif line.startswith("tx bitrate:"):
            d["bitrate"] = line.split(":", 1)[1].strip().split(" MBit")[0] + " Mbit/s"
        elif line.startswith("SSID:"):
            d["ssid"] = line.split(":", 1)[1].strip()
    return d


def phy_modes(phy):
    rc, out, _ = run(["iw", "phy", phy, "info"])
    modes, grab = [], False
    for line in out.splitlines():
        if "Supported interface modes:" in line:
            grab = True
            continue
        if grab:
            s = line.strip()
            if s.startswith("* "):
                modes.append(s[2:].strip())
            else:
                break
    return modes


def nm_state(iface):
    if not has("nmcli"):
        return None
    rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device"])
    for line in out.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if parts and parts[0] == iface:
            return {"state": parts[1] if len(parts) > 1 else "", "conn": parts[2] if len(parts) > 2 else ""}
    return None


def nm_managed(iface):
    s = nm_state(iface)
    return bool(s) and not s["state"].startswith("unmanaged")


def stats(iface):
    base = f"/sys/class/net/{iface}/statistics/"
    keys = ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"]
    out = {}
    for k in keys:
        try:
            out[k] = int(read_file(base + k, "0"))
        except ValueError:
            out[k] = 0
    return out


def iface_summary(iface, addrs=None):
    addrs = addrs if addrs is not None else get_addrs(iface).get(iface, [])
    d = {
        "name": iface,
        "type": iface_type(iface),
        "state": read_file(f"/sys/class/net/{iface}/operstate", "?"),
        "flags_up": bool(int(read_file(f"/sys/class/net/{iface}/flags", "0x0"), 16) & 1),
        "mac": read_file(f"/sys/class/net/{iface}/address", "-"),
        "mtu": read_file(f"/sys/class/net/{iface}/mtu", "-"),
        "ipv4": [f"{a['local']}/{a['prefixlen']}" for a in addrs if a["family"] == "inet"],
        "ipv6": [f"{a['local']}/{a['prefixlen']}" for a in addrs if a["family"] == "inet6"],
        "driver": get_driver(iface),
    }
    if d["type"] == "wifi":
        d.update(iw_info(iface))
    return d


def state_style(s):
    return {"up": "bold green", "down": "bold red", "dormant": "yellow", "unknown": "cyan"}.get(s, "white")


def ifaces_table(numbered=False, only=None):
    addrs = get_addrs()
    t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}", expand=False)
    if numbered:
        t.add_column("#", style=f"bold {ACCENT}", justify="right")
    for c in ["Interface", "Type", "State", "MAC", "IPv4", "Mode", "Driver"]:
        t.add_column(c)
    names = only if only is not None else list_ifaces()
    for i, n in enumerate(names, 1):
        s = iface_summary(n, addrs.get(n, []))
        mode = s.get("mode", "-")
        mode_txt = Text(mode, style="bold yellow" if mode == "monitor" else "white")
        row = [Text(n, style="bold white"), Text(s["type"], style="cyan"),
               Text(s["state"].upper(), style=state_style(s["state"])),
               Text(s["mac"], style="magenta"),
               Text("\n".join(s["ipv4"]) or "-", style="green"), mode_txt, Text(s["driver"], style=DIM)]
        if numbered:
            row.insert(0, str(i))
        t.add_row(*row)
    return t


def pick_iface(title="Select interface", wireless_only=False, include_lo=False):
    names = list_ifaces(include_lo)
    if wireless_only:
        names = [n for n in names if is_wireless(n)]
    if not names:
        err("No suitable interfaces found")
        pause()
        return None
    console.print(Align.center(ifaces_table(numbered=True, only=names)))
    console.print(f"  [{DIM}]0 = back[/]")
    while True:
        v = ask(title, default="1" if len(names) == 1 else None)
        if v in ("0", "", "q"):
            return None
        if v.isdigit() and 1 <= int(v) <= len(names):
            return names[int(v) - 1]
        if v in names:
            return v
        err("Invalid selection")


# ════════════════════════════════════════════════════════════════════
#  1. Overview / Inspector / Live monitor
# ════════════════════════════════════════════════════════════════════

def show_overview():
    header("Interfaces Overview")
    console.print(Align.center(ifaces_table()))
    rc, out, _ = run(["ip", "-j", "route", "show", "default"])
    try:
        routes = json.loads(out or "[]")
    except ValueError:
        routes = []
    gw = ", ".join(f"{r.get('gateway', '-')} via {r.get('dev')}" for r in routes) or "none"
    dns = [l.split()[1] for l in read_file("/etc/resolv.conf").splitlines() if l.startswith("nameserver")]
    console.print()
    console.print(Align.center(Text.assemble(("Default gateway: ", DIM), (gw, "bold green"),
                                             ("   DNS: ", DIM), (", ".join(dns) or "-", "bold cyan"))))
    pause()


def detail_panel(iface):
    s = iface_summary(iface)
    st = stats(iface)
    pm = perm_mac(iface)
    nm = nm_state(iface)
    speed = read_file(f"/sys/class/net/{iface}/speed", "")
    t = Table.grid(padding=(0, 2))
    t.add_column(style=f"bold {ACCENT}", justify="right")
    t.add_column(style="white")
    t.add_row("Interface", Text(iface, style="bold white"))
    t.add_row("Type / Driver", f"{s['type']} / {s['driver']}")
    t.add_row("State", Text(s["state"].upper(), style=state_style(s["state"])))
    mac_txt = Text(s["mac"], style="magenta")
    if pm and pm != s["mac"]:
        mac_txt.append(f"  (permanent {pm})", style="yellow")
    t.add_row("MAC", mac_txt)
    t.add_row("MTU", s["mtu"])
    if speed and speed.lstrip("-").isdigit() and int(speed) > 0:
        t.add_row("Link speed", f"{speed} Mb/s")
    t.add_row("IPv4", Text("\n".join(s["ipv4"]) or "-", style="green"))
    t.add_row("IPv6", Text("\n".join(s["ipv6"]) or "-", style="green"))
    if nm:
        t.add_row("NetworkManager", f"{nm['state']} {('(' + nm['conn'] + ')') if nm['conn'] else ''}")
    if s["type"] == "wifi":
        t.add_row("Wi-Fi mode", Text(s.get("mode", "-"), style="bold yellow" if s.get("mode") == "monitor" else "white"))
        for k, lbl in [("ssid", "SSID"), ("channel", "Channel"), ("signal", "Signal"), ("bitrate", "Bitrate"), ("txpower", "TX power")]:
            if s.get(k):
                t.add_row(lbl, s[k])
        phy = get_phy(iface)
        if phy:
            modes = phy_modes(phy)
            t.add_row("PHY / modes", f"{phy}: " + ", ".join(modes))
    t.add_row("RX", f"{human_bytes(st['rx_bytes']).strip()}  ({st['rx_packets']:,} pkts, {st['rx_errors']} err, {st['rx_dropped']} drop)")
    t.add_row("TX", f"{human_bytes(st['tx_bytes']).strip()}  ({st['tx_packets']:,} pkts, {st['tx_errors']} err, {st['tx_dropped']} drop)")
    return Panel(t, title=f"[bold {ACCENT}]{iface}[/]", border_style=ACCENT, padding=(1, 2), expand=False)


def live_all():
    header("Live Traffic Monitor")
    info("Press Ctrl+C to stop")
    hist = {}
    prev = {i: (stats(i), time.time()) for i in list_ifaces(True)}

    def build():
        addrs = get_addrs()
        t = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {ACCENT2}", border_style=ACCENT, expand=False)
        for c, j in [("Iface", "left"), ("State", "left"), ("IPv4", "left"), ("↓ RX/s", "right"), ("↑ TX/s", "right"),
                     ("pkt/s ↓/↑", "right"), ("Total ↓", "right"), ("Total ↑", "right"), ("Err/Drop", "right"), ("Activity", "left")]:
            t.add_column(c, justify=j)
        now = time.time()
        for i in list_ifaces(True):
            cur = stats(i)
            p, pt = prev.get(i, (cur, now))
            dtm = max(0.001, now - pt)
            rx = (cur["rx_bytes"] - p["rx_bytes"]) / dtm
            tx = (cur["tx_bytes"] - p["tx_bytes"]) / dtm
            rxp = (cur["rx_packets"] - p["rx_packets"]) / dtm
            txp = (cur["tx_packets"] - p["tx_packets"]) / dtm
            prev[i] = (cur, now)
            h = hist.setdefault(i, deque(maxlen=30))
            h.append(rx + tx)
            state = read_file(f"/sys/class/net/{i}/operstate", "?")
            ed = cur["rx_errors"] + cur["tx_errors"], cur["rx_dropped"] + cur["tx_dropped"]
            ips = [f"{a['local']}" for a in addrs.get(i, []) if a["family"] == "inet"]
            t.add_row(Text(i, style="bold white"), Text(state.upper(), style=state_style(state)),
                      Text(", ".join(ips) or "-", style="green"),
                      Text(human_rate(rx), style="bold cyan"), Text(human_rate(tx), style="bold magenta"),
                      f"{rxp:,.0f}/{txp:,.0f}", human_bytes(cur["rx_bytes"]), human_bytes(cur["tx_bytes"]),
                      Text(f"{ed[0]}/{ed[1]}", style="red" if any(ed) else DIM),
                      Text(sparkline(h, 30), style="bright_green"))
        return Panel(t, title=f"[bold {ACCENT}]Live traffic — {dt.datetime.now():%H:%M:%S}[/]",
                     border_style=ACCENT, subtitle="[grey50]Ctrl+C to exit[/]")

    try:
        with Live(build(), console=console, refresh_per_second=4, screen=False) as live:
            while True:
                time.sleep(1)
                live.update(build())
    except KeyboardInterrupt:
        pass


def live_one(iface):
    rxh, txh = deque(maxlen=60), deque(maxlen=60)
    prev, pt = stats(iface), time.time()
    peak = [0, 0]
    total_start = prev.copy()
    t0 = time.time()

    def build():
        nonlocal prev, pt
        cur, now = stats(iface), time.time()
        d = max(0.001, now - pt)
        rx = (cur["rx_bytes"] - prev["rx_bytes"]) / d
        tx = (cur["tx_bytes"] - prev["tx_bytes"]) / d
        rxp = (cur["rx_packets"] - prev["rx_packets"]) / d
        txp = (cur["tx_packets"] - prev["tx_packets"]) / d
        prev, pt = cur, now
        rxh.append(rx)
        txh.append(tx)
        peak[0], peak[1] = max(peak[0], rx), max(peak[1], tx)
        el = max(1, now - t0)
        avg_rx = (cur["rx_bytes"] - total_start["rx_bytes"]) / el
        avg_tx = (cur["tx_bytes"] - total_start["tx_bytes"]) / el
        g = Table.grid(padding=(0, 2))
        g.add_column(style="bold", justify="right")
        g.add_column()
        g.add_row(Text("↓ RX", style="bold cyan"), Text(sparkline(rxh, 60), style="cyan"))
        g.add_row("", Text(f"now {human_rate(rx)}  avg {human_rate(avg_rx)}  peak {human_rate(peak[0])}  {rxp:,.0f} pkt/s", style=DIM))
        g.add_row(Text("↑ TX", style="bold magenta"), Text(sparkline(txh, 60), style="magenta"))
        g.add_row("", Text(f"now {human_rate(tx)}  avg {human_rate(avg_tx)}  peak {human_rate(peak[1])}  {txp:,.0f} pkt/s", style=DIM))
        g.add_row("", "")
        g.add_row(Text("Errors", style="bold red"), f"rx {cur['rx_errors']}  tx {cur['tx_errors']}   dropped rx {cur['rx_dropped']}  tx {cur['tx_dropped']}")
        g.add_row(Text("Session", style="bold green"), f"{int(el)}s   ↓ {human_bytes(cur['rx_bytes'] - total_start['rx_bytes']).strip()}   ↑ {human_bytes(cur['tx_bytes'] - total_start['tx_bytes']).strip()}")
        return Group(detail_panel(iface), Panel(g, title=f"[bold {ACCENT2}]Live graph[/]", border_style=ACCENT2,
                                                subtitle="[grey50]Ctrl+C to exit[/]"))

    header(f"Inspector — {iface}")
    try:
        with Live(build(), console=console, refresh_per_second=2) as live:
            while True:
                time.sleep(1)
                live.update(build())
    except KeyboardInterrupt:
        pass


def inspector():
    header("Interface Inspector")
    iface = pick_iface()
    if iface:
        live_one(iface)


# ════════════════════════════════════════════════════════════════════
#  2. Packet capture & analyzer
# ════════════════════════════════════════════════════════════════════

PROTO_COLORS = [
    (re.compile(r"\bARP\b"), "bold green"),
    (re.compile(r"\bICMP6?\b", re.I), "bold magenta"),
    (re.compile(r"\.(53|5353)\b|\bdomain\b"), "bold yellow"),
    (re.compile(r"\.(443|80|8080)\b"), "bold cyan"),
    (re.compile(r"\bUDP\b"), "yellow"),
    (re.compile(r"Flags \["), "cyan"),
]


def color_packet(line):
    style = "white"
    for rx, st in PROTO_COLORS:
        if rx.search(line):
            style = st
            break
    t = Text(line, style=style)
    t.highlight_regex(r"\d{2}:\d{2}:\d{2}\.\d+", DIM)
    t.highlight_regex(r"Flags \[[^\]]*\]", "bold red")
    return t


def need(tool, pkg=None):
    if has(tool):
        return True
    err(f"'{tool}' is not installed.")
    if confirm(f"Install package '{pkg or tool}' with apt now?", True):
        rc = subprocess.call(["apt-get", "install", "-y", pkg or tool])
        return rc == 0 and has(tool)
    return False


def capture_live():
    header("Live Packet Capture")
    if not need("tcpdump"):
        return pause()
    iface = pick_iface(include_lo=True)
    if not iface:
        return
    console.print(f"  [{DIM}]BPF filter examples: 'tcp port 443', 'udp', 'host 8.8.8.8', 'not port 22', 'icmp or arp'[/]")
    flt = ask("Filter (empty = everything)", default="")
    count = ask_int("Max packets (0 = until Ctrl+C)", default=0, lo=0)
    verbose = confirm("Show link-layer (MAC) headers?", False)
    save = confirm("Also save to .pcap file?", False)
    cmd = ["tcpdump", "-i", iface, "-n", "-l", "-tttt"]
    if verbose:
        cmd.append("-e")
    if count:
        cmd += ["-c", str(count)]
    pcap = None
    if save:
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        pcap = os.path.join(CAPTURE_DIR, f"{iface}_{dt.datetime.now():%Y%m%d_%H%M%S}.pcap")
        cmd += ["-w", pcap, "--print", "-U"]
    if flt:
        cmd += flt.split()
    console.rule(f"[bold {ACCENT}]capturing on {iface}[/]  [grey50]Ctrl+C to stop[/]")
    n = 0
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            n += 1
            console.print(Text(f"{n:>6} ", style=DIM) + color_packet(line.rstrip()))
    except KeyboardInterrupt:
        pass
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            _, e = proc.communicate(timeout=3)
        except Exception:
            proc.kill()
            e = ""
    console.rule()
    if e and "listening" not in e and n == 0:
        err(e.strip()[:400])
    ok(f"{n} packets displayed")
    if pcap and os.path.exists(pcap):
        ok(f"Saved: [bold]{pcap}[/]  (open with wireshark)")
    pause()


def split_hostport(addr):
    if addr.count(".") == 4:          # IPv4 a.b.c.d.port
        h, p = addr.rsplit(".", 1)
        return h, p
    if ":" in addr and "." in addr:   # IPv6 with .port
        h, p = addr.rsplit(".", 1)
        return h, p
    return addr, None


def analyze_traffic():
    header("Traffic Analyzer")
    if not need("tcpdump"):
        return pause()
    iface = pick_iface(include_lo=True)
    if not iface:
        return
    secs = ask_int("Capture duration (seconds)", default=15, lo=1, hi=3600)
    flt = ask("Optional BPF filter", default="")
    cmd = ["timeout", "-s", "INT", str(secs), "tcpdump", "-i", iface, "-n", "-q", "-t", "-l"] + (flt.split() if flt else [])
    with console.status(f"[bold cyan]Capturing on {iface} for {secs}s ...", spinner="dots12"):
        rc, out, e = run(cmd, timeout=secs + 10)
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines:
        err("No packets captured. " + (e.strip().splitlines()[-1] if e.strip() else ""))
        return pause()
    protos, src, dst, ports, conv = Counter(), Counter(), Counter(), Counter(), Counter()
    bytes_by_src = Counter()
    rx = re.compile(r"^(IP6?) (\S+) > (\S+?): (\w+)")
    for l in lines:
        m = rx.match(l)
        if not m:
            protos[l.split(",")[0].split()[0]] += 1
            continue
        fam, s, d, proto = m.groups()
        proto = proto.upper()
        if proto in ("TCP", "UDP") or proto.startswith("ICMP"):
            pass
        else:
            proto = proto[:10]
        protos[f"{fam}/{proto}"] += 1
        sh, sp = split_hostport(s)
        dh, dp = split_hostport(d)
        src[sh] += 1
        dst[dh] += 1
        lm = re.search(r"(?:length |tcp |udp )(\d+)", l, re.I)
        size = int(lm.group(1)) if lm else 0
        bytes_by_src[sh] += size
        if dp and dp.isdigit():
            ports[f"{proto.lower()}/{dp}"] += 1
        conv[f"{sh} → {dh}"] += 1

    def tbl(title, counter, color, extra=None):
        t = Table(title=f"[bold {color}]{title}[/]", box=box.SIMPLE, header_style=f"bold {color}")
        t.add_column("Item")
        t.add_column("Pkts", justify="right")
        if extra:
            t.add_column("Bytes", justify="right")
        total = sum(counter.values()) or 1
        t.add_column("%", justify="right")
        for k, v in counter.most_common(10):
            row = [k, str(v)]
            if extra:
                row.append(human_bytes(extra.get(k, 0)).strip())
            row.append(f"{v * 100 / total:4.1f}")
            t.add_row(*row)
        return t

    header(f"Traffic Analyzer — {iface} ({secs}s)")
    console.print(Align.center(Text(f"{len(lines)} packets  •  {len(lines) / secs:.1f} pkt/s", style="bold green")))
    console.print(Columns([tbl("Protocols", protos, "cyan"), tbl("Top talkers (src)", src, "magenta", bytes_by_src),
                           tbl("Top destinations", dst, "yellow")], align="center"))
    console.print(Columns([tbl("Destination ports", ports, "green"), tbl("Conversations", conv, "bright_blue")], align="center"))
    pause()


def list_captures():
    header("Saved Captures")
    files = sorted(os.listdir(CAPTURE_DIR)) if os.path.isdir(CAPTURE_DIR) else []
    if not files:
        warn("No captures saved yet")
        return pause()
    t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}")
    t.add_column("#", justify="right")
    t.add_column("File")
    t.add_column("Size", justify="right")
    for i, f in enumerate(files, 1):
        t.add_row(str(i), f, human_bytes(os.path.getsize(os.path.join(CAPTURE_DIR, f))))
    console.print(Align.center(t))
    console.print(f"  [{DIM}]Directory: {CAPTURE_DIR}[/]")
    v = ask("Number to read with tcpdump, 'd<num>' to delete, Enter to go back", default="")
    if v.isdigit() and 1 <= int(v) <= len(files):
        rc, out, _ = run(["tcpdump", "-n", "-tttt", "-r", os.path.join(CAPTURE_DIR, files[int(v) - 1])])
        for line in out.splitlines()[:500]:
            console.print(color_packet(line))
        pause()
    elif v.startswith("d") and v[1:].isdigit() and 1 <= int(v[1:]) <= len(files):
        os.remove(os.path.join(CAPTURE_DIR, files[int(v[1:]) - 1]))
        ok("Deleted")
        pause()


def packets_menu():
    while True:
        c = menu("Packet Capture & Analysis", [
            ("1", "Live capture", "colored real-time packet view (optional .pcap save)"),
            ("2", "Traffic analyzer", "capture N seconds → protocols, top talkers, ports"),
            ("3", "Saved captures", "browse / read / delete .pcap files"),
            ("0", "Back", ""),
        ], color="bright_green")
        if c == "0":
            return
        {"1": capture_live, "2": analyze_traffic, "3": list_captures}[c]()


# ════════════════════════════════════════════════════════════════════
#  3. IP / link management
# ════════════════════════════════════════════════════════════════════

def dhcp_renew(iface):
    if nm_managed(iface):
        step(["nmcli", "device", "reapply", iface], "NetworkManager reapply") or \
            (step(["nmcli", "device", "disconnect", iface]) and step(["nmcli", "device", "connect", iface]))
    elif has("dhclient"):
        run(["dhclient", "-r", iface])
        step(["dhclient", iface], "dhclient renew")
    elif has("dhcpcd"):
        step(["dhcpcd", "-n", iface], "dhcpcd renew")
    else:
        err("No DHCP client available (NetworkManager unmanaged, no dhclient/dhcpcd)")


def ip_manage():
    header("IP / Link Management")
    iface = pick_iface()
    if not iface:
        return
    while True:
        header(f"IP / Link — {iface}")
        console.print(Align.center(detail_panel(iface)))
        c = menu_inline([
            ("1", "Add IP address"), ("2", "Remove IP address"), ("3", "Flush all IPv4"),
            ("4", "DHCP renew"), ("5", "Bring UP"), ("6", "Bring DOWN"),
            ("7", "Set MTU"), ("8", "Add default route via this iface"), ("0", "Back"),
        ])
        if c == "0":
            return
        if c == "1":
            v = ask("IP/prefix (e.g. 192.168.1.50/24)")
            try:
                ipaddress.ip_interface(v)
                step(["ip", "addr", "add", v, "dev", iface])
            except ValueError:
                err("Invalid address")
        elif c == "2":
            addrs = [f"{a['local']}/{a['prefixlen']}" for a in get_addrs(iface).get(iface, [])]
            for i, a in enumerate(addrs, 1):
                console.print(f"   [{ACCENT}]{i}[/] {a}")
            v = ask("Number to remove", default="")
            if v.isdigit() and 1 <= int(v) <= len(addrs):
                step(["ip", "addr", "del", addrs[int(v) - 1], "dev", iface])
        elif c == "3":
            if confirm(f"Flush all IPv4 addresses of {iface}?"):
                step(["ip", "-4", "addr", "flush", "dev", iface])
        elif c == "4":
            dhcp_renew(iface)
        elif c == "5":
            step(["ip", "link", "set", iface, "up"])
        elif c == "6":
            if confirm(f"Bring {iface} DOWN? (you may lose connectivity)"):
                step(["ip", "link", "set", iface, "down"])
        elif c == "7":
            m = ask_int("MTU", default=1500, lo=68, hi=65535)
            step(["ip", "link", "set", iface, "mtu", str(m)])
        elif c == "8":
            gw = ask("Gateway IP")
            metric = ask_int("Metric", default=50, lo=0)
            step(["ip", "route", "replace", "default", "via", gw, "dev", iface, "metric", str(metric)])
        pause()


def menu_inline(options, color=ACCENT2):
    line = Text("  ")
    for k, label in options:
        line.append(f"[{k}] ", style=f"bold {color}")
        line.append(f"{label}   ", style="white")
    console.print(Panel(line, border_style=color, box=box.ROUNDED))
    keys = [k for k, _ in options]
    while True:
        c = Prompt.ask(f"  [bold {color}]›[/]").strip().lower()
        if c in keys:
            return c
        err("Invalid choice")


# ════════════════════════════════════════════════════════════════════
#  4. MAC changer
# ════════════════════════════════════════════════════════════════════

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def random_mac(oui=None):
    if oui:
        b = [int(x, 16) for x in oui.split(":")[:3]] + [random.randint(0, 255) for _ in range(3)]
    else:
        b = [random.randint(0, 255) for _ in range(6)]
        b[0] = (b[0] & 0xFC) | 0x02   # locally administered, unicast
    return ":".join(f"{x:02x}" for x in b)


def set_mac(iface, mac):
    mac = mac.lower()
    if not MAC_RE.match(mac):
        err("Invalid MAC format")
        return False
    if int(mac[:2], 16) & 1:
        err("That is a multicast MAC (first byte odd) – not allowed for an interface")
        return False
    st = load_state()
    cur = read_file(f"/sys/class/net/{iface}/address")
    if iface not in st["orig_mac"]:
        st["orig_mac"][iface] = perm_mac(iface) or cur
        save_state(st)
    was_up = read_file(f"/sys/class/net/{iface}/operstate") != "down" or \
        bool(int(read_file(f"/sys/class/net/{iface}/flags", "0x0"), 16) & 1)
    run(["ip", "link", "set", iface, "down"])
    rc, _, e = run(["ip", "link", "set", iface, "address", mac])
    if was_up:
        run(["ip", "link", "set", iface, "up"])
    new = read_file(f"/sys/class/net/{iface}/address")
    if rc == 0 and new == mac:
        ok(f"{iface}: [magenta]{cur}[/] → [bold magenta]{new}[/]")
        if nm_managed(iface):
            warn("NetworkManager manages this device; it may re-apply its own MAC on reconnect "
                 "(see 'cloned-mac-address' in the connection profile).")
        return True
    err(f"Failed to change MAC: {e.strip()}")
    return False


def mac_menu():
    header("MAC Address Changer")
    iface = pick_iface()
    if not iface:
        return
    while True:
        st = load_state()
        cur = read_file(f"/sys/class/net/{iface}/address")
        pm = perm_mac(iface)
        saved = st["orig_mac"].get(iface)
        header(f"MAC Changer — {iface}")
        g = Table.grid(padding=(0, 2))
        g.add_column(style=f"bold {ACCENT}", justify="right")
        g.add_column(style="bold magenta")
        g.add_row("Current", cur)
        g.add_row("Permanent (HW)", pm or "unknown")
        g.add_row("Saved original", saved or "-")
        g.add_row("Status", Text("SPOOFED" if pm and cur != pm else "original", style="bold yellow" if pm and cur != pm else "bold green"))
        console.print(Align.center(Panel(g, border_style=ACCENT2, title=f"[bold]{iface}[/]")))
        c = menu_inline([("1", "Random MAC"), ("2", "Random, keep vendor"), ("3", "Custom MAC"),
                         ("4", "Restore original"), ("5", "Restore permanent (HW)"), ("6", "Restore ALL ifaces"), ("0", "Back")])
        if c == "0":
            return
        if c == "1":
            set_mac(iface, random_mac())
        elif c == "2":
            set_mac(iface, random_mac(oui=pm or cur))
        elif c == "3":
            set_mac(iface, ask("New MAC (xx:xx:xx:xx:xx:xx)"))
        elif c == "4":
            target = saved or pm
            if target and set_mac(iface, target):
                st = load_state()
                st["orig_mac"].pop(iface, None)
                save_state(st)
            elif not target:
                warn("No saved original MAC for this interface")
        elif c == "5":
            if pm and set_mac(iface, pm):
                st = load_state()
                st["orig_mac"].pop(iface, None)
                save_state(st)
            elif not pm:
                err("Permanent MAC could not be read (ethtool -P)")
        elif c == "6":
            restore_all_macs()
        pause()


def restore_all_macs():
    st = load_state()
    if not st["orig_mac"]:
        info("Nothing to restore")
        return
    for iface, mac in list(st["orig_mac"].items()):
        if not os.path.exists(f"/sys/class/net/{iface}"):
            warn(f"{iface} no longer exists – skipped")
            continue
        if set_mac(iface, mac):
            st = load_state()
            st["orig_mac"].pop(iface, None)
            save_state(st)


# ════════════════════════════════════════════════════════════════════
#  5. Wireless & monitor mode
# ════════════════════════════════════════════════════════════════════

def svc_active(name):
    return run(["systemctl", "is-active", "--quiet", name])[0] == 0


def monitor_enable(iface, channel=None, aggressive=False):
    st = load_state()
    if iface in st["monitor"]:
        warn(f"{iface} is already in monitor mode under NetForge control")
        return False
    phy = get_phy(iface)
    if not phy:
        err(f"{iface} is not a wireless interface")
        return False
    modes = phy_modes(phy)
    if "monitor" not in modes:
        err(f"{phy} does not support monitor mode (supported: {', '.join(modes)})")
        return False
    inf = iw_info(iface)
    addrs = get_addrs(iface).get(iface, [])
    backup = {
        "iface": iface, "phy": phy,
        "mode": inf.get("mode", "managed"),
        "mac": read_file(f"/sys/class/net/{iface}/address"),
        "mtu": read_file(f"/sys/class/net/{iface}/mtu"),
        "was_up": bool(int(read_file(f"/sys/class/net/{iface}/flags", "0x0"), 16) & 1),
        "nm_managed": nm_managed(iface),
        "addrs": [f"{a['local']}/{a['prefixlen']}" for a in addrs if a["family"] == "inet" and not a["dynamic"]],
        "stopped_services": [],
        "created_vif": None,
        "monitor_iface": iface,
        "time": dt.datetime.now().isoformat(timespec="seconds"),
    }
    st["monitor"][iface] = backup     # save before touching anything (crash-safe)
    save_state(st)
    info(f"State of {iface} backed up (mode={backup['mode']}, mac={backup['mac']}, NM={'yes' if backup['nm_managed'] else 'no'})")

    if aggressive:
        for svc in ("NetworkManager", "wpa_supplicant"):
            if svc_active(svc) and step(["systemctl", "stop", svc], f"stop {svc}"):
                backup["stopped_services"].append(svc)
        run(["pkill", "-f", f"wpa_supplicant.*{iface}"])
    elif backup["nm_managed"]:
        step(["nmcli", "device", "set", iface, "managed", "no"], f"NetworkManager: release {iface}")
        time.sleep(1)

    run(["ip", "link", "set", iface, "down"])
    rc, _, e = run(["iw", "dev", iface, "set", "type", "monitor"])
    target = iface
    if rc == 0:
        ok(f"{iface} switched to monitor type")
        step(["ip", "link", "set", iface, "up"], f"bring {iface} up")
    else:
        warn(f"Direct switch failed ({e.strip()}) – creating a monitor virtual interface instead")
        vif = (iface + "mon")[:15]
        if run(["iw", "phy", phy, "interface", "add", vif, "type", "monitor"])[0] != 0:
            err("Could not create monitor interface – rolling back")
            st["monitor"][iface] = backup
            save_state(st)
            monitor_restore(iface)
            return False
        backup["created_vif"] = vif
        target = vif
        step(["ip", "link", "set", vif, "up"], f"bring {vif} up")
    backup["monitor_iface"] = target
    st = load_state()
    st["monitor"][iface] = backup
    save_state(st)
    if channel:
        step(["iw", "dev", target, "set", "channel", str(channel)], f"set channel {channel}")
    mode = iw_info(target).get("mode")
    if mode == "monitor":
        ok(f"[bold yellow]{target}[/] is now in [bold yellow]MONITOR[/] mode")
        return True
    err(f"{target} reports mode '{mode}'")
    return False


def monitor_restore(iface):
    st = load_state()
    b = st["monitor"].get(iface)
    if not b:
        warn(f"No NetForge backup for {iface}; doing a generic switch back to managed")
        run(["ip", "link", "set", iface, "down"])
        step(["iw", "dev", iface, "set", "type", "managed"], f"{iface} → managed")
        step(["ip", "link", "set", iface, "up"])
        if has("nmcli"):
            run(["nmcli", "device", "set", iface, "managed", "yes"])
        return
    info(f"Restoring {iface} to its state from {b['time']}")
    if b.get("created_vif"):
        vif = b["created_vif"]
        if os.path.exists(f"/sys/class/net/{vif}"):
            run(["ip", "link", "set", vif, "down"])
            step(["iw", "dev", vif, "del"], f"remove {vif}")
    if os.path.exists(f"/sys/class/net/{iface}"):
        run(["ip", "link", "set", iface, "down"])
        mode = b.get("mode") or "managed"
        if mode == "monitor":
            mode = "managed"
        step(["iw", "dev", iface, "set", "type", mode], f"{iface} → {mode}")
        if read_file(f"/sys/class/net/{iface}/address") != b["mac"]:
            step(["ip", "link", "set", iface, "address", b["mac"]], f"restore MAC {b['mac']}")
        if b.get("mtu"):
            run(["ip", "link", "set", iface, "mtu", b["mtu"]])
        if b.get("was_up"):
            step(["ip", "link", "set", iface, "up"], f"bring {iface} up")
            if not b.get("nm_managed"):
                for a in b.get("addrs", []):
                    run(["ip", "addr", "add", a, "dev", iface])
    else:
        err(f"{iface} no longer exists (driver reloaded / renamed?)")
    for svc in reversed(b.get("stopped_services", [])):
        step(["systemctl", "start", svc], f"start {svc}")
    if b.get("nm_managed") and has("nmcli"):
        time.sleep(1 if not b.get("stopped_services") else 3)
        step(["nmcli", "device", "set", iface, "managed", "yes"], f"NetworkManager: manage {iface} again")
        run(["nmcli", "device", "connect", iface], timeout=20)
    st = load_state()
    st["monitor"].pop(iface, None)
    save_state(st)
    ok(f"[bold green]{iface} fully restored[/] (mode {iw_info(iface).get('mode', '?')})")


def restore_all_monitor():
    st = load_state()
    if not st["monitor"]:
        info("No interfaces in NetForge-controlled monitor mode")
        return
    for iface in list(st["monitor"]):
        monitor_restore(iface)


def wifi_table():
    st = load_state()
    t = Table(box=box.ROUNDED, border_style="yellow", header_style="bold yellow")
    for c in ["#", "Interface", "PHY", "Mode", "Channel", "MAC", "Monitor capable", "NetForge backup"]:
        t.add_column(c)
    names = [n for n in list_ifaces() if is_wireless(n)]
    for i, n in enumerate(names, 1):
        inf = iw_info(n)
        phy = get_phy(n) or "-"
        cap = "monitor" in phy_modes(phy) if phy != "-" else False
        owner = next((k for k, b in st["monitor"].items() if k == n or b.get("created_vif") == n), None)
        t.add_row(str(i), Text(n, style="bold white"), phy,
                  Text(inf.get("mode", "-"), style="bold yellow" if inf.get("mode") == "monitor" else "green"),
                  inf.get("channel", "-"), read_file(f"/sys/class/net/{n}/address"),
                  Text("yes" if cap else "no", style="green" if cap else "red"),
                  Text(f"saved ({owner})" if owner else "-", style="cyan" if owner else DIM))
    return t, names


def wifi_scan():
    header("Wi-Fi Scan")
    iface = pick_iface(wireless_only=True)
    if not iface:
        return
    if iw_info(iface).get("mode") == "monitor":
        err("Interface is in monitor mode – restore it first (or use airodump-ng)")
        return pause()
    nets = []
    if has("nmcli") and nm_managed(iface):
        with console.status("[bold cyan]Scanning ...", spinner="earth"):
            rc, out, _ = run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "device", "wifi",
                              "list", "ifname", iface, "--rescan", "yes"], timeout=30)
        for line in out.splitlines():
            p = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
            if len(p) >= 7:
                nets.append({"use": p[0] == "*", "ssid": p[1] or "<hidden>", "bssid": p[2], "chan": p[3],
                             "freq": p[4], "signal": int(p[5] or 0), "sec": p[6] or "OPEN"})
    else:
        run(["ip", "link", "set", iface, "up"])
        with console.status("[bold cyan]Scanning (iw) ...", spinner="earth"):
            rc, out, e = run(["iw", "dev", iface, "scan"], timeout=30)
        cur = None
        for line in out.splitlines():
            if line.startswith("BSS "):
                cur = {"use": "associated" in line, "bssid": line[4:21], "ssid": "<hidden>", "chan": "-",
                       "freq": "-", "signal": 0, "sec": "OPEN"}
                nets.append(cur)
            elif cur is not None:
                s = line.strip()
                if s.startswith("SSID:"):
                    cur["ssid"] = s[5:].strip() or "<hidden>"
                elif s.startswith("freq:"):
                    cur["freq"] = s[5:].strip()
                elif s.startswith("signal:"):
                    dbm = float(s.split()[1])
                    cur["signal"] = max(0, min(100, int(2 * (dbm + 100))))
                elif "primary channel:" in s:
                    cur["chan"] = s.split(":")[1].strip()
                elif s.startswith("RSN:"):
                    cur["sec"] = "WPA2/3"
                elif s.startswith("WPA:") and cur["sec"] == "OPEN":
                    cur["sec"] = "WPA"
    if not nets:
        err("No networks found")
        return pause()
    nets.sort(key=lambda n: -n["signal"])
    t = Table(box=box.ROUNDED, border_style="yellow", header_style="bold yellow", title=f"[bold]{len(nets)} networks[/]")
    for c in ["", "SSID", "BSSID", "Ch", "Signal", "", "Security"]:
        t.add_column(c)
    for n in nets:
        sig = n["signal"]
        col = "green" if sig >= 65 else "yellow" if sig >= 40 else "red"
        bar = "█" * (sig // 10) + "░" * (10 - sig // 10)
        t.add_row("[bold green]●[/]" if n["use"] else "", Text(n["ssid"], style="bold white"), n["bssid"], n["chan"],
                  Text(f"{sig}%", style=col), Text(bar, style=col),
                  Text(n["sec"], style="red" if n["sec"] in ("OPEN", "--") else "cyan"))
    console.print(Align.center(t))
    pause()


def wireless_menu():
    while True:
        header("Wireless & Monitor Mode")
        t, names = wifi_table()
        console.print(Align.center(t))
        c = menu_inline([("1", "Enable monitor"), ("2", "Restore (exit monitor)"), ("3", "Restore ALL"),
                         ("4", "Set channel"), ("5", "Injection test"), ("6", "Wi-Fi scan"), ("7", "Set TX power"),
                         ("0", "Back")], color="yellow")
        if c == "0":
            return
        if c == "6":
            wifi_scan()
            continue
        if c == "3":
            restore_all_monitor()
            pause()
            continue
        if c == "2":
            st = load_state()
            cands = list(st["monitor"].keys()) + [n for n in names if iw_info(n).get("mode") == "monitor"
                                                   and n not in st["monitor"]
                                                   and not any(b.get("created_vif") == n for b in st["monitor"].values())]
            if not cands:
                warn("No interface is in monitor mode")
                pause()
                continue
            for i, n in enumerate(cands, 1):
                tag = "(NetForge backup → exact restore)" if n in st["monitor"] else "(no backup → generic restore)"
                console.print(f"   [bold yellow]{i}[/] {n} [{DIM}]{tag}[/]")
            v = ask("Which one", default="1")
            if v.isdigit() and 1 <= int(v) <= len(cands):
                monitor_restore(cands[int(v) - 1])
            pause()
            continue
        if not names:
            err("No wireless interfaces")
            pause()
            continue
        v = ask("Interface number", default="1")
        if not (v.isdigit() and 1 <= int(v) <= len(names)):
            continue
        iface = names[int(v) - 1]
        if c == "1":
            ch = ask("Channel (empty = keep current)", default="")
            console.print(f"  [{DIM}]Soft mode: only this card is released from NetworkManager (other cards keep working).\n"
                          f"  Aggressive mode: stops NetworkManager + wpa_supplicant entirely (like airmon-ng check kill).[/]")
            aggressive = confirm("Use aggressive mode?", False)
            monitor_enable(iface, int(ch) if ch.isdigit() else None, aggressive)
        elif c == "4":
            ch = ask_int("Channel", default=6, lo=1, hi=196)
            step(["iw", "dev", iface, "set", "channel", str(ch)], f"{iface} → channel {ch}")
        elif c == "5":
            if iw_info(iface).get("mode") != "monitor":
                err("Interface must be in monitor mode")
            elif need("aireplay-ng", "aircrack-ng"):
                console.rule("[yellow]aireplay-ng --test[/]")
                subprocess.call(["aireplay-ng", "--test", iface])
                console.rule()
        elif c == "7":
            dbm = ask_int("TX power in dBm (e.g. 20)", default=20, lo=0, hi=40)
            step(["iw", "dev", iface, "set", "txpower", "fixed", str(dbm * 100)], f"{iface} txpower {dbm} dBm")
        pause()


# ════════════════════════════════════════════════════════════════════
#  6. SSH proxy manager
# ════════════════════════════════════════════════════════════════════

USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
UNIT_TEMPLATE = f"""[Unit]
Description=NetForge SSH proxy on port %i
After=network.target

[Service]
ExecStartPre=/usr/bin/mkdir -p -m0755 /run/sshd
ExecStartPre={SSHD} -t -f {SSH_CONF_DIR}/sshd_%i.conf
ExecStart={SSHD} -D -f {SSH_CONF_DIR}/sshd_%i.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def proxy_unit(port):
    return f"netforge-sshd@{port}.service"


def proxy_active(port):
    return svc_active(proxy_unit(port))


def group_exists(g):
    return run(["getent", "group", g])[0] == 0


def user_exists(u):
    return run(["getent", "passwd", u])[0] == 0


def user_in_proxy_group(u):
    rc, out, _ = run(["id", "-gn", u])
    return rc == 0 and out.strip() == PROXY_GROUP


def ensure_ssh_ready():
    if not os.path.exists(SSHD):
        if not need("sshd", "openssh-server"):
            return False
    os.makedirs(SSH_CONF_DIR, exist_ok=True)
    run(["ssh-keygen", "-A"])
    if read_file(UNIT_FILE) != UNIT_TEMPLATE.strip():
        with open(UNIT_FILE, "w") as f:
            f.write(UNIT_TEMPLATE)
        run(["systemctl", "daemon-reload"])
    if not group_exists(PROXY_GROUP):
        run(["groupadd", "--system", PROXY_GROUP])
    # Prevent proxy users from using the main system sshd (port 22)
    if os.path.isdir("/etc/ssh/sshd_config.d") and not os.path.exists(DENY_DROPIN):
        with open(DENY_DROPIN, "w") as f:
            f.write(f"# Added by NetForge: proxy-only accounts cannot use the main SSH server\nDenyGroups {PROXY_GROUP}\n")
        if svc_active("ssh"):
            run(["systemctl", "reload", "ssh"])
    return True


def write_proxy_conf(port, p):
    users = " ".join(p["users"].keys()) or "__nobody__"
    keys = "\n".join(f"HostKey {k}" for k in ["/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ecdsa_key",
                                               "/etc/ssh/ssh_host_rsa_key"] if os.path.exists(k))
    banner = ""
    if p.get("banner"):
        bfile = os.path.join(SSH_CONF_DIR, f"banner_{port}.txt")
        with open(bfile, "w") as f:
            f.write(p["banner"] + "\n")
        banner = f"Banner {bfile}"
    conf = f"""# Generated by NetForge – do not edit by hand
Port {port}
ListenAddress {p.get('listen', '0.0.0.0')}
PidFile /run/netforge-sshd-{port}.pid
{keys}
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
PermitEmptyPasswords no
UsePAM yes
AllowUsers {users}
AllowTcpForwarding yes
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no
PermitTTY no
PrintMotd no
PrintLastLog no
UseDNS no
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 4
MaxAuthTries 4
MaxSessions 20
MaxStartups 50:30:200
LoginGraceTime 30
LogLevel INFO
SyslogFacility AUTH
{banner}
"""
    path = os.path.join(SSH_CONF_DIR, f"sshd_{port}.conf")
    with open(path, "w") as f:
        f.write(conf)
    os.chmod(path, 0o600)
    rc, _, e = run([SSHD, "-t", "-f", path])
    if rc != 0:
        err(f"sshd config test failed: {e.strip()}")
        return False
    return True


def port_in_use(port):
    rc, out, _ = run(["ss", "-Htln", f"sport = :{port}"])
    return bool(out.strip())


def gen_password(n=12):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def create_proxy_user(name, password, expire=None):
    if not USER_RE.match(name):
        err(f"Invalid username '{name}' (lowercase letters, digits, _ and -, start with a letter)")
        return False
    if user_exists(name):
        if not user_in_proxy_group(name):
            err(f"'{name}' is an existing system account – refusing to touch it. Choose another name.")
            return False
        err(f"'{name}' is already a proxy user (usernames must be unique across proxies)")
        return False
    cmd = ["useradd", "-M", "-N", "-g", PROXY_GROUP, "-s", "/bin/false", "-d", "/nonexistent"]
    if expire:
        cmd += ["-e", expire]
    cmd.append(name)
    rc, _, e = run(cmd)
    if rc != 0:
        err(f"useradd failed: {e.strip()}")
        return False
    rc, _, e = run(["chpasswd"], input_text=f"{name}:{password}\n")
    if rc != 0:
        err(f"chpasswd failed: {e.strip()}")
        run(["userdel", name])
        return False
    return True


def delete_proxy_user(name):
    if user_exists(name) and user_in_proxy_group(name):
        run(["pkill", "-KILL", "-u", name])
        time.sleep(0.3)
        run(["userdel", "-f", name])


_public_ip_cache = [None, 0]


def public_ip():
    if _public_ip_cache[0] and time.time() - _public_ip_cache[1] < 600:
        return _public_ip_cache[0]
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        rc, out, _ = run(["curl", "-s", "--max-time", "4", url])
        out = out.strip()
        try:
            ipaddress.ip_address(out)
            _public_ip_cache[:] = [out, time.time()]
            return out
        except ValueError:
            continue
    return None


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def ask_expire():
    v = ask("Expire after how many days? (0 = never)", default="0")
    if v.isdigit() and int(v) > 0:
        return (dt.date.today() + dt.timedelta(days=int(v))).isoformat()
    return None


def ask_users(p):
    """Interactively add users to proxy dict p."""
    while True:
        name = ask("Username (empty to finish)", default="")
        if not name:
            break
        pw = ask("Password (empty = random)", default="", password=False) or gen_password()
        exp = ask_expire()
        if create_proxy_user(name, pw, exp):
            p["users"][name] = {"password": pw, "expire": exp, "created": dt.date.today().isoformat()}
            ok(f"User [bold]{name}[/] created (password: [bold green]{pw}[/]{', expires ' + exp if exp else ''})")


def start_proxy(port):
    run(["systemctl", "enable", proxy_unit(port)])
    rc, _, e = run(["systemctl", "restart", proxy_unit(port)])
    time.sleep(0.7)
    if proxy_active(port):
        ok(f"SSH proxy on port [bold]{port}[/] is [bold green]RUNNING[/]")
        return True
    err(f"Service failed to start: {e.strip()}")
    rc, out, _ = run(["journalctl", "-u", proxy_unit(port), "-n", "8", "--no-pager"])
    console.print(Text(out, style=DIM))
    return False


def open_firewall(port, close=False):
    if has("ufw") and "Status: active" in run(["ufw", "status"])[1]:
        run(["ufw", "delete", "allow", f"{port}/tcp"] if close else ["ufw", "allow", f"{port}/tcp"])
        info(f"ufw: port {port}/tcp {'closed' if close else 'opened'}")


def create_proxy():
    header("Create SSH Proxy")
    if not ensure_ssh_ready():
        return pause()
    st = load_state()
    while True:
        port = ask_int("Port", default=random.randint(20000, 60000), lo=1, hi=65535)
        if str(port) in st["proxies"]:
            err("A NetForge proxy already uses this port")
        elif port_in_use(port):
            err("Port is already in use by another program")
        else:
            break
    listen = ask("Listen address", default="0.0.0.0")
    banner = ask("Optional login banner text (empty = none)", default="")
    p = {"port": port, "listen": listen, "users": {}, "banner": banner,
         "created": dt.datetime.now().isoformat(timespec="seconds")}
    info("Now add users for this proxy")
    ask_users(p)
    if not p["users"]:
        err("A proxy needs at least one user – cancelled")
        return pause()
    if not write_proxy_conf(port, p):
        for u in p["users"]:
            delete_proxy_user(u)
        return pause()
    st = load_state()
    st["proxies"][str(port)] = p
    save_state(st)
    open_firewall(port)
    start_proxy(port)
    show_conn_info(str(port))


def bulk_create():
    header("Bulk Create SSH Proxies")
    if not ensure_ssh_ready():
        return pause()
    count = ask_int("How many proxies", default=3, lo=1, hi=500)
    start = ask_int("Start port", default=30000, lo=1, hi=65535)
    users_per = ask_int("Users per proxy", default=1, lo=1, hi=100)
    prefix = ask("Username prefix", default="user")
    fixed_pw = ask("Same password for all (empty = random each)", default="")
    exp = ask_expire()
    st = load_state()
    created = []
    port = start
    uid = 1
    with console.status("[bold cyan]Creating proxies ...", spinner="dots"):
        for _ in range(count):
            while port <= 65535 and (str(port) in st["proxies"] or port_in_use(port)):
                port += 1
            if port > 65535:
                err("Ran out of ports")
                break
            p = {"port": port, "listen": "0.0.0.0", "users": {}, "banner": "",
                 "created": dt.datetime.now().isoformat(timespec="seconds")}
            for _ in range(users_per):
                while user_exists(f"{prefix}{uid}"):
                    uid += 1
                name, pw = f"{prefix}{uid}", fixed_pw or gen_password()
                if create_proxy_user(name, pw, exp):
                    p["users"][name] = {"password": pw, "expire": exp, "created": dt.date.today().isoformat()}
                uid += 1
            if p["users"] and write_proxy_conf(port, p):
                st["proxies"][str(port)] = p
                save_state(st)
                open_firewall(port)
                run(["systemctl", "enable", "--now", proxy_unit(port)])
                created.append(str(port))
            port += 1
    time.sleep(1)
    ok(f"Created {len(created)} proxies")
    export_proxies(created)


def export_proxies(ports=None):
    st = load_state()
    ports = ports or list(st["proxies"])
    host = public_ip() or local_ip()
    t = Table(box=box.ROUNDED, border_style="green", header_style="bold green")
    for c in ["Port", "Status", "User", "Password", "Expires", "Connection string"]:
        t.add_column(c)
    lines = []
    for port in ports:
        p = st["proxies"].get(port)
        if not p:
            continue
        status = Text("●", style="bold green") if proxy_active(port) else Text("●", style="bold red")
        for u, d in p["users"].items():
            s = f"{host}:{port}@{u}:{d['password']}"
            lines.append(s)
            t.add_row(port, status, u, d["password"], d.get("expire") or "never", Text(s, style="cyan"))
    console.print(Align.center(t))
    if lines and confirm("Save this list to a text file?", False):
        path = os.path.join(STATE_DIR, f"proxies_{dt.datetime.now():%Y%m%d_%H%M%S}.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(path, 0o600)
        ok(f"Saved to {path}")
    pause()


def proxy_sessions(port):
    rc, out, _ = run(["ss", "-Htn", "state", "established", f"( sport = :{port} )"])
    peers = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            peers.append(parts[3])
    return peers


def user_sessions(user):
    rc, out, _ = run(["pgrep", "-c", "-u", user])
    try:
        return int(out.strip() or 0)
    except ValueError:
        return 0


def show_conn_info(port):
    st = load_state()
    p = st["proxies"].get(port)
    if not p:
        return
    host = public_ip()
    lip = local_ip()
    rows = []
    for u, d in p["users"].items():
        rows.append(Text.assemble(("● ", "bold green"), (u, "bold white"), ("  pass: ", DIM), (d["password"], "bold green"),
                                  ("  expires: ", DIM), (d.get("expire") or "never", "yellow")))
    first = next(iter(p["users"]), "USER")
    body = Group(
        Text.assemble(("Server  ", f"bold {ACCENT}"), (f"{host or '?'}  (public)   {lip}  (LAN)", "white")),
        Text.assemble(("Port    ", f"bold {ACCENT}"), (port, "bold white")),
        Text(""),
        *rows,
        Text(""),
        Text("Use as SOCKS5 proxy on a client:", style=f"bold {ACCENT2}"),
        Text(f"  ssh -N -D 1080 -p {port} {first}@{host or lip}", style="cyan"),
        Text("  then set browser/system SOCKS5 proxy → 127.0.0.1:1080", style=DIM),
        Text("Apps (HTTP Injector, NapsternetV, Termius ...):", style=f"bold {ACCENT2}"),
        Text(f"  {host or lip}:{port}@{first}:{p['users'].get(first, {}).get('password', 'PASS')}", style="cyan"),
    )
    console.print(Align.center(Panel(body, title=f"[bold green]SSH proxy :{port}[/]", border_style="green", padding=(1, 3))))
    if host and host != lip and ipaddress.ip_address(lip).is_private:
        console.print(f"  [{DIM}]Behind NAT? Forward TCP port {port} on your router to {lip} for access from the Internet.[/]")
    pause()


def test_proxy(port):
    st = load_state()
    p = st["proxies"].get(port)
    if not p or not p["users"]:
        return
    if not proxy_active(port):
        err("Service is not running")
        return
    user = next(iter(p["users"]))
    pw = p["users"][user]["password"]
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        lport = s.getsockname()[1]
    tmpdir = tempfile.mkdtemp(prefix="nf-")
    askpass = os.path.join(tmpdir, "askpass.sh")
    with open(askpass, "w") as f:
        f.write('#!/bin/sh\nprintf "%s\\n" "$NF_PASS"\n')
    os.chmod(askpass, 0o700)
    env = dict(os.environ, SSH_ASKPASS=askpass, SSH_ASKPASS_REQUIRE="force", NF_PASS=pw, DISPLAY=":0")
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
           "-o", "PreferredAuthentications=password", "-o", "ConnectTimeout=8",
           "-N", "-D", f"127.0.0.1:{lport}", "-p", port, f"{user}@127.0.0.1"]
    info(f"Testing as [bold]{user}[/]: opening SOCKS tunnel on 127.0.0.1:{lport} ...")
    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            start_new_session=True)
    try:
        up = False
        for _ in range(40):
            time.sleep(0.25)
            if proc.poll() is not None:
                break
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", lport)) == 0:
                    up = True
                    break
        if not up:
            e = proc.stderr.read().decode(errors="replace") if proc.poll() is not None else "timeout"
            err(f"Tunnel could not be established: {e.strip()}")
            return
        ok("SSH authentication OK, SOCKS tunnel is up")
        t0 = time.time()
        rc, out, e = run(["curl", "-s", "--max-time", "10", "--socks5-hostname", f"127.0.0.1:{lport}",
                          "https://api.ipify.org"], timeout=15)
        if rc == 0 and out.strip():
            ok(f"Internet through proxy works – exit IP [bold green]{out.strip()}[/] ({(time.time() - t0) * 1000:.0f} ms)")
        else:
            warn("Tunnel works but the test HTTP request failed (no internet on server?)")
    finally:
        if proc.poll() is None:
            proc.terminate()
        shutil.rmtree(tmpdir, ignore_errors=True)


def delete_proxy(port, ask_confirm=True):
    st = load_state()
    p = st["proxies"].get(port)
    if not p:
        return
    if ask_confirm and not confirm(f"Delete proxy :{port} and its {len(p['users'])} user(s)?"):
        return
    run(["systemctl", "disable", "--now", proxy_unit(port)])
    for u in p["users"]:
        delete_proxy_user(u)
    for f in (f"sshd_{port}.conf", f"banner_{port}.txt"):
        try:
            os.remove(os.path.join(SSH_CONF_DIR, f))
        except OSError:
            pass
    open_firewall(port, close=True)
    st = load_state()
    st["proxies"].pop(port, None)
    save_state(st)
    ok(f"Proxy :{port} deleted")


def manage_proxy(port):
    while True:
        st = load_state()
        p = st["proxies"].get(port)
        if not p:
            return
        header(f"SSH Proxy :{port}")
        active = proxy_active(port)
        peers = proxy_sessions(port)
        t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}",
                  title=Text.assemble(("Port ", "white"), (port, "bold white"), ("  •  ", DIM),
                                      ("RUNNING" if active else "STOPPED", "bold green" if active else "bold red"),
                                      ("  •  listen ", DIM), (p.get("listen", "0.0.0.0"), "white"),
                                      ("  •  connections ", DIM), (str(len(peers)), "bold cyan")))
        for c in ["#", "User", "Password", "Expires", "Online procs", "Created"]:
            t.add_column(c)
        users = list(p["users"])
        today = dt.date.today().isoformat()
        for i, u in enumerate(users, 1):
            d = p["users"][u]
            exp = d.get("expire")
            expired = exp and exp < today
            n = user_sessions(u)
            t.add_row(str(i), Text(u, style="bold white"), d["password"],
                      Text((exp or "never") + (" EXPIRED" if expired else ""), style="bold red" if expired else "yellow"),
                      Text(str(n), style="bold green" if n else DIM), d.get("created", "-"))
        console.print(Align.center(t))
        if peers:
            console.print(Align.center(Text("Connected from: " + ", ".join(peers[:12]) + (" ..." if len(peers) > 12 else ""), style="cyan")))
        c = menu_inline([("1", "Add user"), ("2", "Remove user"), ("3", "Change password"), ("4", "Set expiry"),
                         ("5", "Kick user"), ("6", "Start/Restart"), ("7", "Stop"), ("8", "Connection info"),
                         ("9", "Test"), ("l", "Logs"), ("x", "Delete proxy"), ("0", "Back")])
        if c == "0":
            return
        changed = False
        if c == "1":
            ask_users(p)
            changed = True
        elif c in ("2", "3", "4", "5"):
            v = ask("User number", default="1")
            if not (v.isdigit() and 1 <= int(v) <= len(users)):
                continue
            u = users[int(v) - 1]
            if c == "2":
                if len(users) == 1:
                    err("Last user – delete the proxy instead")
                elif confirm(f"Remove {u}?"):
                    delete_proxy_user(u)
                    p["users"].pop(u)
                    changed = True
            elif c == "3":
                pw = ask("New password (empty = random)", default="") or gen_password()
                if run(["chpasswd"], input_text=f"{u}:{pw}\n")[0] == 0:
                    p["users"][u]["password"] = pw
                    ok(f"Password of {u} → [bold green]{pw}[/]")
                    st["proxies"][port] = p
                    save_state(st)
            elif c == "4":
                exp = ask_expire()
                run(["chage", "-E", exp or "-1", u])
                p["users"][u]["expire"] = exp
                st["proxies"][port] = p
                save_state(st)
                ok(f"{u} expires: {exp or 'never'}")
            elif c == "5":
                run(["pkill", "-KILL", "-u", u])
                ok(f"All sessions of {u} terminated")
        elif c == "6":
            start_proxy(port)
        elif c == "7":
            step(["systemctl", "disable", "--now", proxy_unit(port)], f"stop proxy :{port}")
        elif c == "8":
            show_conn_info(port)
            continue
        elif c == "9":
            test_proxy(port)
        elif c == "l":
            rc, out, _ = run(["journalctl", "-u", proxy_unit(port), "-n", "40", "--no-pager", "-o", "short-iso"])
            for line in out.splitlines():
                style = "red" if "Failed" in line or "Invalid" in line else "green" if "Accepted" in line else DIM
                console.print(Text(line, style=style))
        elif c == "x":
            delete_proxy(port)
            pause()
            return
        if changed:
            st["proxies"][port] = p
            save_state(st)
            if write_proxy_conf(port, p) and proxy_active(port):
                run(["systemctl", "reload", proxy_unit(port)])
                ok("Proxy configuration reloaded")
        pause()


def proxies_table():
    st = load_state()
    t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}")
    for c in ["#", "Port", "Status", "Listen", "Users", "Connections", "Created"]:
        t.add_column(c)
    ports = sorted(st["proxies"], key=int)
    for i, port in enumerate(ports, 1):
        p = st["proxies"][port]
        a = proxy_active(port)
        t.add_row(str(i), Text(port, style="bold white"),
                  Text("● RUNNING" if a else "● STOPPED", style="bold green" if a else "bold red"),
                  p.get("listen", "0.0.0.0"), ", ".join(p["users"])[:40], str(len(proxy_sessions(port))),
                  p.get("created", "-")[:16].replace("T", " "))
    return t, ports


def ssh_menu():
    while True:
        header("SSH Proxy Manager")
        t, ports = proxies_table()
        if ports:
            console.print(Align.center(t))
        else:
            console.print(Align.center(Text("No proxies yet – create one!", style="yellow")))
        c = menu_inline([("1", "Create proxy"), ("2", "Bulk create"), ("3", "Manage proxy"), ("4", "Export all"),
                         ("5", "Start all"), ("6", "Stop all"), ("7", "Clean expired users"), ("8", "Delete ALL"),
                         ("0", "Back")], color="green")
        if c == "0":
            return
        if c == "1":
            create_proxy()
        elif c == "2":
            bulk_create()
        elif c == "3":
            if not ports:
                continue
            v = ask("Proxy # or port", default="1")
            if v in ports:
                manage_proxy(v)
            elif v.isdigit() and 1 <= int(v) <= len(ports):
                manage_proxy(ports[int(v) - 1])
        elif c == "4":
            export_proxies()
        elif c in ("5", "6"):
            for port in ports:
                if c == "5":
                    run(["systemctl", "enable", proxy_unit(port)])
                    step(["systemctl", "restart", proxy_unit(port)], f"start :{port}")
                else:
                    step(["systemctl", "disable", "--now", proxy_unit(port)], f"stop :{port}")
            pause()
        elif c == "7":
            st = load_state()
            today = dt.date.today().isoformat()
            n = 0
            for port, p in st["proxies"].items():
                for u in [u for u, d in p["users"].items() if d.get("expire") and d["expire"] < today]:
                    run(["pkill", "-KILL", "-u", u])
                    n += 1
                    info(f"{u} on :{port} is expired – sessions killed (account kept, login disabled by system)")
            ok(f"{n} expired user(s) handled")
            pause()
        elif c == "8":
            if ports and confirm(f"Really delete ALL {len(ports)} proxies and their users?"):
                for port in ports:
                    delete_proxy(port, ask_confirm=False)
            pause()


# ════════════════════════════════════════════════════════════════════
#  6b. SSH tunnel proxies (client side: this PC → remote server)
# ════════════════════════════════════════════════════════════════════

TUN_DIR = os.path.join(STATE_DIR, "tunnels")
TUN_KNOWN_HOSTS = os.path.join(STATE_DIR, "known_hosts")
TUN_ASKPASS = os.path.join(STATE_DIR, "askpass.sh")
TUN_KEY = os.path.join(STATE_DIR, "id_ed25519")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
SSH = shutil.which("ssh") or "/usr/bin/ssh"


def tun_unit(name):
    return f"netforge-tunnel-{name}.service"


def tun_unit_path(name):
    return f"/etc/systemd/system/{tun_unit(name)}"


def tun_passfile(name):
    return os.path.join(TUN_DIR, f"{name}.pass")


def tun_prepare():
    os.makedirs(TUN_DIR, mode=0o700, exist_ok=True)
    if read_file(TUN_ASKPASS) != '#!/bin/sh\ncat "$NF_PASSFILE"':
        with open(TUN_ASKPASS, "w") as f:
            f.write('#!/bin/sh\ncat "$NF_PASSFILE"\n')
        os.chmod(TUN_ASKPASS, 0o700)


def tun_ssh_opts(t):
    o = ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={TUN_KNOWN_HOSTS}",
         "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
         "-o", "LogLevel=ERROR", "-p", str(t["ssh_port"])]
    if t["auth"] == "key":
        o += ["-i", t["key"], "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no"]
    else:
        o += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
    return o


def tun_cmd(t):
    flags = ["-N", "-o", "ExitOnForwardFailure=yes"]
    if t.get("compress"):
        flags.append("-C")
    return [SSH] + flags + ["-D", f"{t['bind']}:{t['local_port']}"] + tun_ssh_opts(t) + [f"{t['user']}@{t['host']}"]


def tun_env(passfile):
    return {"SSH_ASKPASS": TUN_ASKPASS, "SSH_ASKPASS_REQUIRE": "force", "NF_PASSFILE": passfile, "DISPLAY": ":0"}


def tun_write_unit(name, t):
    cmd = " ".join(tun_cmd(t))
    env = ""
    if t["auth"] == "password":
        env = "\n".join(f"Environment={k}={v}" for k, v in tun_env(tun_passfile(name)).items())
    unit = f"""[Unit]
Description=NetForge SSH tunnel {name} ({t['user']}@{t.get('label') or t['host']} -> socks {t['bind']}:{t['local_port']})
After=network-online.target {t.get('after') or ''}
Wants=network-online.target {t.get('after') or ''}
StartLimitIntervalSec=0

[Service]
{env}
ExecStart={cmd}
StandardInput=null
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(tun_unit_path(name), "w") as f:
        f.write(unit)
    os.chmod(tun_unit_path(name), 0o600)
    run(["systemctl", "daemon-reload"])


def tun_listening(t):
    with socket.socket() as s:
        s.settimeout(0.5)
        host = "127.0.0.1" if t["bind"] in ("0.0.0.0", "127.0.0.1") else t["bind"]
        return s.connect_ex((host, int(t["local_port"]))) == 0


def tun_status(name, t):
    if not svc_active(tun_unit(name)):
        return "stopped"
    return "up" if tun_listening(t) else "connecting"


def tun_test(t, quiet=False):
    host = "127.0.0.1" if t["bind"] in ("0.0.0.0", "127.0.0.1") else t["bind"]
    t0 = time.time()
    rc, out, _ = run(["curl", "-s", "--max-time", "12", "--socks5-hostname", f"{host}:{t['local_port']}",
                      "https://api.ipify.org"], timeout=15)
    ms = (time.time() - t0) * 1000
    out = out.strip()
    try:
        ipaddress.ip_address(out)
    except ValueError:
        if not quiet:
            err("Request through the proxy failed")
        return None, None
    if not quiet:
        ok(f"Proxy works – exit IP [bold green]{out}[/]  latency [bold yellow]{ms:.0f} ms[/]")
    return out, ms


def tun_start(name, t, wait=20):
    run(["systemctl", "enable", tun_unit(name)])
    run(["systemctl", "restart", tun_unit(name)])
    with console.status(f"[bold cyan]Connecting {t['user']}@{t['host']}:{t['ssh_port']} ...", spinner="dots12"):
        for _ in range(wait * 2):
            time.sleep(0.5)
            if tun_listening(t):
                break
    if tun_listening(t):
        ok(f"Tunnel [bold]{name}[/] is UP → SOCKS5 [bold cyan]{t['bind']}:{t['local_port']}[/]")
        return True
    err("Tunnel did not come up. Last log lines:")
    rc, out, _ = run(["journalctl", "-u", tun_unit(name), "-n", "8", "--no-pager", "-o", "cat"])
    console.print(Text(out.strip() or "(no log)", style="red"))
    hint = out.lower()
    if "permission denied" in hint:
        warn("Wrong username / password / key")
    elif "host key verification failed" in hint or "remote host identification has changed" in hint:
        warn("Server host key changed – use 'Forget host key' in the tunnel menu")
    elif "address already in use" in hint:
        warn("Local port is busy – pick another local port")
    return False


def tun_stop(name):
    run(["systemctl", "disable", "--now", tun_unit(name)])


def tun_usage_panel(t):
    host = "127.0.0.1" if t["bind"] in ("0.0.0.0", "127.0.0.1") else t["bind"]
    p = t["local_port"]
    lines = [
        Text.assemble(("SOCKS5 proxy  ", f"bold {ACCENT}"), (f"{host}:{p}", "bold white"), ("   (no username / password)", DIM)),
        Text(""),
        Text("Terminal (one command):", style=f"bold {ACCENT2}"),
        Text(f"  curl --socks5-hostname {host}:{p} https://api.ipify.org", style="cyan"),
        Text("Terminal (whole session):", style=f"bold {ACCENT2}"),
        Text(f"  export ALL_PROXY=socks5h://{host}:{p}      # undo:  unset ALL_PROXY", style="cyan"),
        Text("Firefox:", style=f"bold {ACCENT2}"),
        Text(f"  Settings → Network → Manual proxy → SOCKS Host {host}  Port {p}", style="cyan"),
        Text("  SOCKS v5  +  ✔ Proxy DNS when using SOCKS v5", style="cyan"),
        Text("Chromium:", style=f"bold {ACCENT2}"),
        Text(f"  chromium --proxy-server=\"socks5://{host}:{p}\"", style="cyan"),
    ]
    if t["bind"] == "0.0.0.0":
        lines += [Text("Other devices on your LAN (phone, laptop):", style=f"bold {ACCENT2}"),
                  Text(f"  SOCKS5  {local_ip()}:{p}", style="cyan")]
    return Panel(Group(*lines), title="[bold green]How to use[/]", border_style="green", padding=(1, 2))


def tun_ask_auth(t, name):
    """Ask auth method; writes password file if needed. Returns True if ok."""
    c = menu_inline([("1", "Password"), ("2", "SSH key file"), ("3", "NetForge key (auto-installed on server)")])
    if c == "1":
        pw = ask("Server SSH password", password=True)
        if not pw:
            err("Empty password")
            return False
        fd = os.open(tun_passfile(name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        t["auth"], t["key"] = "password", None
        return True
    if c == "2":
        home = os.path.expanduser(f"~{os.environ.get('SUDO_USER', 'root')}")
        default = next((os.path.join(home, ".ssh", k) for k in ("id_ed25519", "id_rsa", "id_ecdsa")
                        if os.path.exists(os.path.join(home, ".ssh", k))), os.path.join(home, ".ssh", "id_ed25519"))
        key = ask("Private key path", default=default)
        if not os.path.isfile(key):
            err("Key file not found")
            return False
        t["auth"], t["key"] = "key", key
        return True
    # NetForge key: generate once, copy to server using the password
    if not os.path.exists(TUN_KEY):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "netforge", "-f", TUN_KEY])
    pw = ask("Server SSH password (used once to install the key)", password=True)
    with tempfile.TemporaryDirectory() as td:
        pf = os.path.join(td, "p")
        fd = os.open(pf, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        tmp = dict(t, auth="password")
        cmd = ["ssh-copy-id", "-i", TUN_KEY + ".pub"] + tun_ssh_opts(tmp) + [f"{t['user']}@{t['host']}"]
        with console.status("[bold cyan]Installing key on server ...", spinner="dots"):
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                               env=dict(os.environ, **tun_env(pf)))
    if p.returncode != 0:
        err(f"Could not install key: {(p.stderr or p.stdout).strip()[-300:]}")
        return False
    ok("Key installed on server – no password needed from now on")
    t["auth"], t["key"] = "key", TUN_KEY
    return True


def tun_create(preset=None):
    if not preset:
        header("New SSH Tunnel Proxy")
    tun_prepare()
    st = load_state()
    if preset:
        name = preset["name"]
        if name in st["tunnels"]:
            tun_delete(name, ask_confirm=False)
            st = load_state()
        t = {"host": preset["host"], "ssh_port": preset["ssh_port"], "after": preset.get("after"),
             "label": preset.get("label")}
    else:
        while True:
            name = ask("Tunnel name (e.g. germany1)")
            if not NAME_RE.match(name):
                err("Use letters, digits, - and _ only")
            elif name in st["tunnels"]:
                err("Name already exists")
            else:
                break
        t = {"host": ask("Server address (IP or domain)")}
        t["ssh_port"] = ask_int("Server SSH port", default=22, lo=1, hi=65535)
    t["user"] = ask("Server username", default="root")
    used = {int(x["local_port"]) for x in st["tunnels"].values()} | \
        {int(x.get("local_port") or x.get("port") or 0) for x in st["obfs4"].values()}
    suggest = next(p for p in range(1080, 65000) if p not in used and not port_in_use(p))
    while True:
        lp = ask_int("Local SOCKS port on this PC", default=suggest, lo=1, hi=65535)
        if lp in used:
            err("Another tunnel uses this port")
        elif port_in_use(lp):
            err("Port is busy on this system")
        else:
            break
    t["local_port"] = lp
    t["bind"] = "0.0.0.0" if confirm("Share the proxy with other devices on your LAN?", False) else "127.0.0.1"
    t["compress"] = confirm("Enable compression (helps on slow links)?", False)
    t["created"] = dt.datetime.now().isoformat(timespec="seconds")
    if not tun_ask_auth(t, name):
        try:
            os.remove(tun_passfile(name))
        except OSError:
            pass
        return pause()
    st = load_state()
    st["tunnels"][name] = t
    save_state(st)
    tun_write_unit(name, t)
    if tun_start(name, t):
        tun_test(t)
        console.print(tun_usage_panel(t))
    else:
        warn("Saved anyway – fix the settings from 'Manage tunnel' (it keeps retrying every 5s)")
    pause()


def tun_delete(name, ask_confirm=True):
    if ask_confirm and not confirm(f"Delete tunnel {name}?"):
        return
    tun_stop(name)
    for f in (tun_unit_path(name), tun_passfile(name)):
        try:
            os.remove(f)
        except OSError:
            pass
    run(["systemctl", "daemon-reload"])
    st = load_state()
    st["tunnels"].pop(name, None)
    save_state(st)
    ok(f"Tunnel {name} deleted")


def tun_manage(name):
    while True:
        st = load_state()
        t = st["tunnels"].get(name)
        if not t:
            return
        header(f"Tunnel — {name}")
        s = tun_status(name, t)
        g = Table.grid(padding=(0, 2))
        g.add_column(style=f"bold {ACCENT}", justify="right")
        g.add_column(style="white")
        g.add_row("Status", Text(s.upper(), style={"up": "bold green", "connecting": "bold yellow"}.get(s, "bold red")))
        g.add_row("Server", f"{t['user']}@{t['host']}:{t['ssh_port']}")
        g.add_row("Auth", t["auth"] + (f" ({t['key']})" if t.get("key") else ""))
        g.add_row("SOCKS5", Text(f"{t['bind']}:{t['local_port']}", style="bold cyan"))
        g.add_row("Compression", "on" if t.get("compress") else "off")
        g.add_row("Created", t.get("created", "-").replace("T", " "))
        console.print(Align.center(Panel(g, border_style=ACCENT, title=f"[bold]{name}[/]", padding=(1, 3))))
        c = menu_inline([("1", "Start/Reconnect"), ("2", "Stop"), ("3", "Test"), ("4", "How to use"),
                         ("5", "Change local port"), ("6", "Change auth"), ("7", "LAN sharing on/off"),
                         ("8", "Forget host key"), ("l", "Logs"), ("x", "Delete"), ("0", "Back")])
        if c == "0":
            return
        if c == "1":
            tun_start(name, t)
        elif c == "2":
            tun_stop(name)
            ok("Stopped")
        elif c == "3":
            if tun_status(name, t) != "up":
                err("Tunnel is not up")
            else:
                with console.status("[bold cyan]Testing ...", spinner="dots"):
                    ip, ms = tun_test(t, quiet=True)
                if ip:
                    ok(f"Proxy works – exit IP [bold green]{ip}[/]  latency [bold yellow]{ms:.0f} ms[/]")
                else:
                    err("Request through the proxy failed")
        elif c == "4":
            console.print(tun_usage_panel(t))
        elif c in ("5", "6", "7"):
            if c == "5":
                lp = ask_int("New local port", default=t["local_port"], lo=1, hi=65535)
                if lp != t["local_port"] and port_in_use(lp):
                    err("Port is busy")
                    pause()
                    continue
                t["local_port"] = lp
            elif c == "6":
                t["user"] = ask("Server username", default=t["user"])
                if not tun_ask_auth(t, name):
                    pause()
                    continue
                if t["auth"] == "key":
                    try:
                        os.remove(tun_passfile(name))
                    except OSError:
                        pass
            else:
                t["bind"] = "127.0.0.1" if t["bind"] == "0.0.0.0" else "0.0.0.0"
                info(f"Bind address → {t['bind']}")
            st = load_state()
            st["tunnels"][name] = t
            save_state(st)
            tun_write_unit(name, t)
            tun_start(name, t)
        elif c == "8":
            run(["ssh-keygen", "-R", f"[{t['host']}]:{t['ssh_port']}" if t["ssh_port"] != 22 else t["host"],
                 "-f", TUN_KNOWN_HOSTS])
            ok("Host key forgotten – the new key will be accepted on next connect")
        elif c == "l":
            rc, out, _ = run(["journalctl", "-u", tun_unit(name), "-n", "30", "--no-pager", "-o", "short-iso"])
            console.print(Text(out.strip() or "(no log)", style=DIM))
        elif c == "x":
            tun_delete(name)
            pause()
            return
        pause()


def external_tunnels():
    """ssh -D processes not managed by NetForge (e.g. started by hand)."""
    rc, out, _ = run(["ps", "-eo", "pid=,user=,args="])
    res = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, user, args = parts
        a = args.split()
        if a and os.path.basename(a[0]) == "ssh" and any(x.startswith("-D") or x == "-D" for x in a) \
                and TUN_KNOWN_HOSTS not in args:
            res.append((pid, user, args))
    return res


def tun_table():
    st = load_state()
    t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}")
    for c in ["#", "Name", "Status", "SOCKS5 (local)", "Server", "Auth", "LAN"]:
        t.add_column(c)
    names = sorted(st["tunnels"])
    for i, n in enumerate(names, 1):
        x = st["tunnels"][n]
        s = tun_status(n, x)
        t.add_row(str(i), Text(n, style="bold white"),
                  Text("● " + s.upper(), style={"up": "bold green", "connecting": "bold yellow"}.get(s, "bold red")),
                  Text(f"127.0.0.1:{x['local_port']}", style="bold cyan"),
                  f"{x['user']}@{x['label']}" if x.get("label") else f"{x['user']}@{x['host']}:{x['ssh_port']}", x["auth"],
                  "yes" if x["bind"] == "0.0.0.0" else "-")
    return t, names


def tunnels_menu():
    while True:
        header("SSH Tunnel Proxies")
        t, names = tun_table()
        if names:
            console.print(Align.center(t))
        else:
            console.print(Align.center(Text("No tunnels yet – create one with [1]", style="yellow")))
        ext = external_tunnels()
        if ext:
            console.print(Align.center(Text(f"⚠ {len(ext)} manual ssh -D tunnel(s) running outside NetForge (see [6])",
                                            style="yellow")))
        c = menu_inline([("1", "New tunnel"), ("2", "Manage"), ("3", "Start all"), ("4", "Stop all"),
                         ("5", "Test all"), ("6", "Manual ssh -D tunnels"), ("b", "obfs4 / Tor bridges"),
                         ("h", "Host SSH server mode"),
                         ("0", "Back")], color="green")
        if c == "0":
            return
        if c == "1":
            tun_create()
        elif c == "2" and names:
            v = ask("Tunnel # or name", default="1")
            if v in names:
                tun_manage(v)
            elif v.isdigit() and 1 <= int(v) <= len(names):
                tun_manage(names[int(v) - 1])
        elif c in ("3", "4", "5"):
            st = load_state()
            for n in names:
                x = st["tunnels"][n]
                if c == "3":
                    tun_start(n, x)
                elif c == "4":
                    tun_stop(n)
                    ok(f"{n} stopped")
                else:
                    if tun_status(n, x) != "up":
                        err(f"{n}: not up")
                        continue
                    ip, ms = tun_test(x, quiet=True)
                    if ip:
                        ok(f"{n}: exit IP [bold green]{ip}[/]  {ms:.0f} ms")
                    else:
                        err(f"{n}: request failed")
            pause()
        elif c == "6":
            ext = external_tunnels()
            if not ext:
                info("No manual ssh -D tunnels running")
            for i, (pid, user, args) in enumerate(ext, 1):
                m = re.search(r"-D\s*(\S+)", args)
                port = m.group(1).rsplit(":", 1)[-1] if m else "?"
                works = tun_listening({"bind": "127.0.0.1", "local_port": port}) if port.isdigit() else False
                console.print(f"   [bold yellow]{i}[/] pid {pid} ({user})  port [cyan]{port}[/]  "
                              f"{'[green]listening[/]' if works else '[red]not listening[/]'}\n      [grey50]{args}[/]")
            if ext:
                v = ask("Number to kill (Enter = keep all)", default="")
                if v.isdigit() and 1 <= int(v) <= len(ext):
                    run(["kill", ext[int(v) - 1][0]])
                    ok("Killed")
            pause()
        elif c == "b":
            obfs4_menu()
        elif c == "h":
            ssh_menu()


# ════════════════════════════════════════════════════════════════════
#  6c. obfs4 proxies (Tor bridges / own obfs4 server / obfs4 server mode)
# ════════════════════════════════════════════════════════════════════

OBFS_DIR = "/var/lib/netforge-obfs4"
FPR_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


def pt_bin():
    return shutil.which("lyrebird") or shutil.which("obfs4proxy") or "/usr/bin/obfs4proxy"


def ob_unit(name):
    return f"netforge-obfs4-{name}.service"


def ob_unit_path(name):
    return f"/etc/systemd/system/{ob_unit(name)}"


def ob_dir(name):
    return os.path.join(OBFS_DIR, name)


def parse_bridge(line):
    """Parse 'Bridge obfs4 IP:PORT [FPR] cert=.. iat-mode=..' → dict or None."""
    tok = line.strip().split()
    if tok and tok[0].lower() == "bridge":
        tok = tok[1:]
    if tok and tok[0].lower() == "obfs4":
        tok = tok[1:]
    if not tok:
        return None
    addr = tok[0]
    m = re.match(r"^\[?([^\]]+?)\]?:(\d+)$", addr)
    if not m:
        return None
    b = {"host": m.group(1), "port": int(m.group(2)), "fingerprint": None, "args": {}}
    for t in tok[1:]:
        if FPR_RE.match(t):
            b["fingerprint"] = t.upper()
        elif "=" in t:
            k, v = t.split("=", 1)
            b["args"][k] = v
    if "cert" not in b["args"]:
        return None
    b["args"].setdefault("iat-mode", "0")
    return b


def bridge_line(b):
    host = f"[{b['host']}]" if ":" in b["host"] else b["host"]
    parts = ["obfs4", f"{host}:{b['port']}"]
    if b.get("fingerprint"):
        parts.append(b["fingerprint"])
    parts += [f"{k}={v}" for k, v in b["args"].items()]
    return " ".join(parts)


# ───────────── obfs4 client forwarder (runs as a systemd service) ─────────────

def pt_socks_auth(args):
    def esc(s):
        return s.replace("\\", "\\\\").replace(";", "\\;").replace("=", "\\=")
    raw = ";".join(f"{esc(k)}={esc(v)}" for k, v in args.items()).encode()
    if len(raw) <= 255:
        return raw, b"\x00"
    return raw[:255], raw[255:]


def run_forwarder(p, statedir):
    """Local plain TCP port  ⇄  obfs4 (via obfs4proxy client)  ⇄  remote server."""
    import asyncio
    import threading
    os.makedirs(statedir, mode=0o700, exist_ok=True)
    env = dict(os.environ, TOR_PT_MANAGED_TRANSPORT_VER="1", TOR_PT_CLIENT_TRANSPORTS="obfs4",
               TOR_PT_STATE_LOCATION=statedir, TOR_PT_EXIT_ON_STDIN_CLOSE="1")
    proc = subprocess.Popen([pt_bin(), "-enableLogging", "-logLevel", "WARN"], env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    socks = None
    for line in proc.stdout:
        line = line.strip()
        print("pt:", line, flush=True)
        if line.startswith("CMETHOD obfs4 socks5"):
            socks = line.split()[3]
        elif "ERROR" in line:
            sys.exit(1)
        elif line == "CMETHODS DONE":
            break
    if not socks:
        print("obfs4proxy did not offer a SOCKS listener", flush=True)
        sys.exit(1)
    sh, sp = socks.rsplit(":", 1)
    b = p["bridge"]
    dst_ip = socket.getaddrinfo(b["host"], b["port"], proto=socket.IPPROTO_TCP)[0][4][0]
    auth = pt_socks_auth(b["args"])
    threading.Thread(target=lambda: (proc.wait(), print("obfs4proxy exited", flush=True), os._exit(1)),
                     daemon=True).start()

    async def pt_connect():
        r, w = await asyncio.open_connection(sh, int(sp))
        w.write(b"\x05\x01\x02")
        await w.drain()
        if await r.readexactly(2) != b"\x05\x02":
            raise ConnectionError("PT refused SOCKS auth method")
        u, pw = auth
        w.write(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
        await w.drain()
        if (await r.readexactly(2))[1] != 0:
            raise ConnectionError("PT rejected obfs4 arguments (bad cert?)")
        ip = ipaddress.ip_address(dst_ip)
        w.write(b"\x05\x01\x00" + (b"\x01" if ip.version == 4 else b"\x04") + ip.packed + int(b["port"]).to_bytes(2, "big"))
        await w.drain()
        hdr = await r.readexactly(4)
        if hdr[1] != 0:
            raise ConnectionError(f"obfs4 handshake/connect failed (SOCKS code {hdr[1]})")
        alen = {1: 4, 4: 16}.get(hdr[3]) or (await r.readexactly(1))[0]
        await r.readexactly(alen + 2)
        return r, w

    async def pipe(r, w):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                if w.can_write_eof():
                    w.write_eof()
            except Exception:
                pass

    async def handle(cr, cw):
        try:
            sr, sw = await asyncio.wait_for(pt_connect(), 30)
        except Exception as e:
            print(f"connect error: {e}", flush=True)
            cw.close()
            return
        await asyncio.gather(pipe(cr, sw), pipe(sr, cw))
        for w in (cw, sw):
            try:
                w.close()
            except Exception:
                pass

    async def main():
        srv = await asyncio.start_server(handle, p["bind"], int(p["local_port"]))
        print(f"listening on {p['bind']}:{p['local_port']} → obfs4 {b['host']}:{b['port']}", flush=True)
        async with srv:
            await srv.serve_forever()

    asyncio.run(main())


def obfs4_forward_main(name):
    p = load_state()["obfs4"].get(name)
    if not p:
        print(f"unknown obfs4 profile {name}", flush=True)
        sys.exit(2)
    run_forwarder(p, os.path.join(ob_dir(name), "pt"))


# ───────────── unit / config writers ─────────────

def tor_user():
    return "debian-tor" if user_exists("debian-tor") else "root"


def write_torrc(name, p, path, datadir):
    lines = [f"DataDirectory {datadir}", f"SocksPort {p['bind']}:{p['local_port']}",
             "UseBridges 1", f"ClientTransportPlugin obfs4 exec {pt_bin()}", "Log notice stdout", "AvoidDiskWrites 1"]
    if p.get("http_port"):
        lines.append(f"HTTPTunnelPort {p['bind']}:{p['http_port']}")
    if p["bind"] != "127.0.0.1":
        lines.append("SocksPolicy accept 127.0.0.0/8, accept 10.0.0.0/8, accept 172.16.0.0/12, accept 192.168.0.0/16, reject *")
    if p.get("exit_country"):
        cc = ",".join("{%s}" % c.strip().lower() for c in p["exit_country"].split(",") if c.strip())
        lines += [f"ExitNodes {cc}", "StrictNodes 1"]
    lines += [f"Bridge {bl}" for bl in p["bridges"]]
    with open(path, "w") as f:
        f.write("# Generated by NetForge\n" + "\n".join(lines) + "\n")


def ob_write_unit(name, p):
    d = ob_dir(name)
    os.makedirs(OBFS_DIR, mode=0o755, exist_ok=True)
    os.makedirs(d, mode=0o700, exist_ok=True)
    common = "Restart=always\nRestartSec=5\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
    if p["type"] == "tor":
        user = tor_user()
        datadir = os.path.join(d, "tor")
        os.makedirs(datadir, mode=0o700, exist_ok=True)
        torrc = os.path.join(d, "torrc")
        write_torrc(name, p, torrc, datadir)
        if user != "root":
            run(["chown", "-R", f"{user}:", d])
        rc, out, e = run(["tor", "--verify-config", "-f", torrc, "--DataDirectory", "/tmp/nf-verify-" + name])
        shutil.rmtree("/tmp/nf-verify-" + name, ignore_errors=True)
        if rc != 0:
            err("torrc check failed: " + (out + e).strip().splitlines()[-1][:300])
            return False
        svc = f"User={user}\nExecStart={shutil.which('tor') or '/usr/sbin/tor'} -f {torrc} --RunAsDaemon 0\n{common}"
        desc = f"Tor via {len(p['bridges'])} obfs4 bridge(s) -> socks {p['bind']}:{p['local_port']}"
    elif p["type"] == "direct":
        script = os.path.realpath(__file__)
        svc = (f"ExecStart={sys.executable} {script} --obfs4-forward {name}\n{common}"
               f"ProtectSystem=strict\nProtectHome=read-only\nReadWritePaths={d}\n")
        desc = f"obfs4 client {p['bridge']['host']}:{p['bridge']['port']} -> local {p['bind']}:{p['local_port']}"
    else:  # server
        pt = os.path.join(d, "pt")
        os.makedirs(pt, mode=0o700, exist_ok=True)
        env = {"TOR_PT_MANAGED_TRANSPORT_VER": "1", "TOR_PT_SERVER_TRANSPORTS": "obfs4",
               "TOR_PT_SERVER_BINDADDR": f"obfs4-{p['bind']}:{p['port']}", "TOR_PT_ORPORT": p["target"],
               "TOR_PT_EXTENDED_SERVER_PORT": "", "TOR_PT_STATE_LOCATION": pt,
               "TOR_PT_SERVER_TRANSPORT_OPTIONS": f"obfs4:iat-mode={p.get('iat', '0')}"}
        envs = "\n".join(f"Environment={k}={v}" for k, v in env.items())
        svc = (f"{envs}\nExecStart={pt_bin()} -enableLogging -logLevel INFO\n{common}"
               f"ProtectSystem=strict\nProtectHome=yes\nReadWritePaths={d}\n")
        desc = f"obfs4 server {p['bind']}:{p['port']} -> {p['target']}"
    unit = (f"[Unit]\nDescription=NetForge {desc}\nAfter=network-online.target\nWants=network-online.target\n"
            f"StartLimitIntervalSec=0\n\n[Service]\n{svc}\n[Install]\nWantedBy=multi-user.target\n")
    with open(ob_unit_path(name), "w") as f:
        f.write(unit)
    run(["systemctl", "daemon-reload"])
    return True


# ───────────── status / start / test ─────────────

def ob_listen_port(p):
    return p["port"] if p["type"] == "server" else p["local_port"]


def tor_bootstrap(name):
    inv = run(["systemctl", "show", "-p", "InvocationID", "--value", ob_unit(name)])[1].strip()
    if not inv:
        return 0, ""
    rc, out, _ = run(["journalctl", f"_SYSTEMD_INVOCATION_ID={inv}", "-o", "cat", "--no-pager"])
    pct, msg = 0, ""
    for line in out.splitlines():
        m = re.search(r"Bootstrapped (\d+)%[^:]*: (.*)", line)
        if m:
            pct, msg = int(m.group(1)), m.group(2)
    return pct, msg


def ob_status(name, p):
    if not svc_active(ob_unit(name)):
        return "stopped"
    if not tun_listening({"bind": p["bind"], "local_port": ob_listen_port(p)}):
        return "starting"
    if p["type"] == "tor":
        pct, _ = tor_bootstrap(name)
        return "up" if pct >= 100 else f"boot {pct}%"
    return "up"


def ob_start(name, p):
    run(["systemctl", "enable", ob_unit(name)])
    run(["systemctl", "restart", ob_unit(name)])
    if p["type"] == "tor":
        from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
        info("Tor is connecting through the bridges (can take 10–120 s, Ctrl+C = leave it running in background)")
        try:
            with Progress(TextColumn("  [bold cyan]{task.description}"), BarColumn(bar_width=40, complete_style="green"),
                          TextColumn("[bold]{task.percentage:>3.0f}%"), TimeElapsedColumn(), console=console) as pr:
                task = pr.add_task("bootstrap", total=100)
                for _ in range(360):
                    time.sleep(0.5)
                    pct, msg = tor_bootstrap(name)
                    pr.update(task, completed=pct, description=(msg or "starting")[:45])
                    if pct >= 100 or not svc_active(ob_unit(name)):
                        break
        except KeyboardInterrupt:
            warn("Still bootstrapping in background")
            return False
        if tor_bootstrap(name)[0] >= 100:
            ok(f"[bold]{name}[/] connected → SOCKS5 [bold cyan]{p['bind']}:{p['local_port']}[/]"
               + (f"  HTTP [bold cyan]{p['bind']}:{p['http_port']}[/]" if p.get("http_port") else ""))
            return True
    else:
        with console.status("[bold cyan]Starting ...", spinner="dots12"):
            for _ in range(30):
                time.sleep(0.5)
                if tun_listening({"bind": p["bind"], "local_port": ob_listen_port(p)}):
                    break
        if tun_listening({"bind": p["bind"], "local_port": ob_listen_port(p)}):
            ok(f"[bold]{name}[/] is running on port [bold cyan]{ob_listen_port(p)}[/]")
            return True
    err("Did not come up. Last log lines:")
    rc, out, _ = run(["journalctl", "-u", ob_unit(name), "-n", "12", "--no-pager", "-o", "cat"])
    console.print(Text(out.strip() or "(no log)", style="red"))
    return False


def ob_test(name, p):
    if p["type"] == "server":
        info("Server mode: test it from a client with the connection line")
        return
    if p["type"] == "direct" and p.get("behind") == "ssh":
        info(f"This is the obfs4 transport for SSH tunnel '{p.get('tunnel')}'. Test that tunnel in menu 8.")
        return
    with console.status("[bold cyan]Testing through the proxy ...", spinner="dots"):
        ip, ms = tun_test({"bind": p["bind"], "local_port": p["local_port"]}, quiet=True)
    if ip:
        ok(f"Proxy works – exit IP [bold green]{ip}[/]  latency [bold yellow]{ms:.0f} ms[/]")
    else:
        err("Request through the proxy failed")


def ob_server_line(name, p):
    bl = read_file(os.path.join(ob_dir(name), "pt", "obfs4_bridgeline.txt"))
    m = re.search(r"cert=(\S+)", bl)
    if not m:
        return None
    host = public_ip() or local_ip()
    return f"obfs4 {host}:{p['port']} cert={m.group(1)} iat-mode={p.get('iat', '0')}"


def ob_usage(name, p):
    if p["type"] == "server":
        line = ob_server_line(name, p)
        body = Group(
            Text.assemble(("Listening ", f"bold {ACCENT}"), (f"{p['bind']}:{p['port']}", "bold white"),
                          ("  →  forwards to ", DIM), (p["target"], "bold white")),
            Text(""), Text("Connection line for clients (NetForge → obfs4 → 'Own obfs4 server'):", style=f"bold {ACCENT2}"),
            Text(f"  {line or '(not generated yet – start the server first)'}", style="bold green"),
            Text(""), Text(f"Open TCP port {p['port']} in your firewall / cloud panel.", style=DIM))
        return Panel(body, title="[bold green]obfs4 server[/]", border_style="green", padding=(1, 2))
    if p["type"] == "direct" and p.get("behind") == "ssh":
        return Panel(Text(f"Transport for SSH tunnel '{p.get('tunnel')}' – use that tunnel's SOCKS port (menu 8).",
                          style="cyan"), border_style="green")
    pan = tun_usage_panel({"bind": p["bind"], "local_port": p["local_port"]})
    if p.get("http_port"):
        h = "127.0.0.1" if p["bind"] in ("0.0.0.0", "127.0.0.1") else p["bind"]
        return Group(pan, Panel(Text(f"HTTP proxy (CONNECT): {h}:{p['http_port']}\n"
                                     f"  export https_proxy=http://{h}:{p['http_port']}", style="cyan"),
                                border_style="green"))
    return pan


# ───────────── creation wizards ─────────────

def ask_bind_and_port(st, default_start):
    used = {int(x.get("local_port") or x.get("port") or 0) for x in st["obfs4"].values()} | \
           {int(x["local_port"]) for x in st["tunnels"].values()}
    suggest = next(q for q in range(default_start, 65000) if q not in used and not port_in_use(q))
    while True:
        lp = ask_int("Local proxy port on this PC", default=suggest, lo=1, hi=65535)
        if lp in used or port_in_use(lp):
            err("Port is busy")
        else:
            break
    bind = "0.0.0.0" if confirm("Share with other devices on your LAN?", False) else "127.0.0.1"
    return lp, bind, used


def ask_ob_name(st):
    while True:
        name = ask("Profile name (e.g. bridges1)")
        if not NAME_RE.match(name):
            err("Use letters, digits, - and _ only")
        elif name in st["obfs4"]:
            err("Name already exists")
        else:
            return name


def ob_save_and_start(name, p):
    st = load_state()
    st["obfs4"][name] = p
    save_state(st)
    if not ob_write_unit(name, p):
        return False
    up = ob_start(name, p)
    if up:
        ob_test(name, p)
    console.print(ob_usage(name, p))
    return up


def ob_create_tor():
    header("obfs4 — Tor with bridges")
    if not need("tor") or not (has("lyrebird") or has("obfs4proxy") or need("obfs4proxy")):
        return pause()
    st = load_state()
    name = ask_ob_name(st)
    console.print(f"  [{DIM}]Paste obfs4 bridge lines one per line (from bridges.torproject.org, Telegram @GetBridgesBot,\n"
                  f"  or email bridges@torproject.org). Empty line to finish.[/]")
    bridges = []
    while True:
        line = Prompt.ask("  [bold cyan]bridge[/]", default="", show_default=False).strip()
        if not line:
            break
        b = parse_bridge(line)
        if not b or not b["fingerprint"]:
            err("Not a valid obfs4 bridge line (needs IP:PORT FINGERPRINT cert=... iat-mode=...)")
            continue
        bridges.append(bridge_line(b))
        ok(f"bridge {b['host']}:{b['port']} added")
    if not bridges:
        err("No bridges – cancelled")
        return pause()
    lp, bind, used = ask_bind_and_port(st, 9150)
    http = None
    if confirm("Also open an HTTP proxy port (for apps without SOCKS support)?", False):
        http = next(q for q in range(lp + 1, 65000) if q not in used and not port_in_use(q))
        http = ask_int("HTTP proxy port", default=http, lo=1, hi=65535)
    cc = ask("Exit country codes, e.g. de,nl (empty = any)", default="")
    p = {"type": "tor", "bridges": bridges, "local_port": lp, "bind": bind, "http_port": http,
         "exit_country": cc, "created": dt.datetime.now().isoformat(timespec="seconds")}
    ob_save_and_start(name, p)
    pause()


def ob_create_direct():
    header("obfs4 — Own obfs4 server")
    if not (has("lyrebird") or has("obfs4proxy") or need("obfs4proxy")):
        return pause()
    st = load_state()
    name = ask_ob_name(st)
    console.print(f"  [{DIM}]Format:  obfs4 SERVER:PORT cert=XXXXXXXX iat-mode=0   (NetForge server mode prints this line)[/]")
    while True:
        b = parse_bridge(ask("Connection line"))
        if b:
            break
        err("Invalid line – it needs at least SERVER:PORT and cert=...")
    console.print(f"  [{DIM}]What runs behind obfs4 on the server?[/]")
    behind = menu_inline([("1", "SOCKS5/HTTP proxy (use directly)"), ("2", "SSH server (build SSH tunnel over it)")])
    p = {"type": "direct", "bridge": b, "created": dt.datetime.now().isoformat(timespec="seconds")}
    if behind == "1":
        lp, bind, _ = ask_bind_and_port(st, 1090)
        p.update(local_port=lp, bind=bind, behind="socks")
        ob_save_and_start(name, p)
        return pause()
    # SSH behind obfs4: internal forward port on 127.0.0.1, then SSH tunnel through it
    used = {int(x.get("local_port") or x.get("port") or 0) for x in st["obfs4"].values()}
    fwd = next(q for q in range(42000, 65000) if q not in used and not port_in_use(q))
    p.update(local_port=fwd, bind="127.0.0.1", behind="ssh", tunnel=name)
    st["obfs4"][name] = p
    save_state(st)
    if not ob_write_unit(name, p) or not ob_start(name, p):
        return pause()
    info(f"obfs4 transport ready on 127.0.0.1:{fwd} – now the SSH login for the server")
    tun_create(preset={"name": name, "host": "127.0.0.1", "ssh_port": fwd, "after": ob_unit(name),
                       "label": f"{b['host']}:{b['port']} via obfs4"})


def ob_create_server():
    header("obfs4 — Server mode (this machine)")
    if not (has("lyrebird") or has("obfs4proxy") or need("obfs4proxy")):
        return pause()
    st = load_state()
    name = ask_ob_name(st)
    used = {int(x.get("local_port") or x.get("port") or 0) for x in st["obfs4"].values()}
    while True:
        port = ask_int("Public obfs4 port", default=random.randint(20000, 60000), lo=1, hi=65535)
        if port in used or port_in_use(port):
            err("Port is busy")
        else:
            break
    target = ask("Forward to (local service: SSH or a SOCKS server)", default="127.0.0.1:22")
    iat = ask("iat-mode (0 = fast, 1/2 = more padding, slower)", default="0")
    p = {"type": "server", "port": port, "bind": "0.0.0.0", "target": target, "iat": iat if iat in "012" else "0",
         "created": dt.datetime.now().isoformat(timespec="seconds")}
    st["obfs4"][name] = p
    save_state(st)
    if ob_write_unit(name, p) and ob_start(name, p):
        open_firewall(port)
        for _ in range(10):
            if ob_server_line(name, p):
                break
            time.sleep(0.5)
        console.print(ob_usage(name, p))
    pause()


def ob_delete(name):
    if not confirm(f"Delete obfs4 profile {name}?"):
        return
    st = load_state()
    p = st["obfs4"].get(name, {})
    if p.get("behind") == "ssh" and p.get("tunnel") in st["tunnels"]:
        tun_delete(p["tunnel"], ask_confirm=False)
    run(["systemctl", "disable", "--now", ob_unit(name)])
    for f in (ob_unit_path(name),):
        try:
            os.remove(f)
        except OSError:
            pass
    shutil.rmtree(ob_dir(name), ignore_errors=True)
    run(["systemctl", "daemon-reload"])
    if p.get("type") == "server":
        open_firewall(p["port"], close=True)
    st = load_state()
    st["obfs4"].pop(name, None)
    save_state(st)
    ok(f"{name} deleted")


def ob_manage(name):
    while True:
        st = load_state()
        p = st["obfs4"].get(name)
        if not p:
            return
        header(f"obfs4 — {name}")
        s = ob_status(name, p)
        g = Table.grid(padding=(0, 2))
        g.add_column(style=f"bold {ACCENT}", justify="right")
        g.add_column(style="white")
        g.add_row("Status", Text(s.upper(), style="bold green" if s == "up" else "bold red" if s == "stopped" else "bold yellow"))
        g.add_row("Type", {"tor": "Tor + obfs4 bridges", "direct": "own obfs4 server", "server": "obfs4 server (this machine)"}[p["type"]])
        if p["type"] == "tor":
            for bl in p["bridges"]:
                g.add_row("Bridge", Text(bl[:90] + ("…" if len(bl) > 90 else ""), style=DIM))
            if p.get("exit_country"):
                g.add_row("Exit country", p["exit_country"])
        elif p["type"] == "direct":
            g.add_row("Server", f"{p['bridge']['host']}:{p['bridge']['port']}  (behind: {p.get('behind')})")
        else:
            g.add_row("Forward to", p["target"])
        g.add_row("Port", Text(f"{p['bind']}:{ob_listen_port(p)}", style="bold cyan"))
        if p.get("http_port"):
            g.add_row("HTTP port", Text(f"{p['bind']}:{p['http_port']}", style="bold cyan"))
        console.print(Align.center(Panel(g, border_style=ACCENT, title=f"[bold]{name}[/]", padding=(1, 3))))
        opts = [("1", "Start/Restart"), ("2", "Stop"), ("3", "Test"), ("4", "How to use / connection line"), ("l", "Logs")]
        if p["type"] == "tor":
            opts += [("5", "Edit bridges"), ("6", "New identity (new circuit)")]
        opts += [("x", "Delete"), ("0", "Back")]
        c = menu_inline(opts, color="yellow")
        if c == "0":
            return
        if c == "1":
            ob_start(name, p)
        elif c == "2":
            run(["systemctl", "disable", "--now", ob_unit(name)])
            ok("Stopped")
        elif c == "3":
            ob_test(name, p)
        elif c == "4":
            console.print(ob_usage(name, p))
        elif c == "l":
            rc, out, _ = run(["journalctl", "-u", ob_unit(name), "-n", "40", "--no-pager", "-o", "short-iso"])
            for line in out.splitlines():
                st_ = "red" if re.search(r"warn|err|fail", line, re.I) else "green" if "Bootstrapped 100" in line else DIM
                console.print(Text(line, style=st_))
        elif c == "5" and p["type"] == "tor":
            for i, bl in enumerate(p["bridges"], 1):
                console.print(f"   [bold yellow]{i}[/] {bl[:100]}")
            v = ask("'a' = add bridges, 'd<num>' = delete one, Enter = back", default="")
            if v == "a":
                while True:
                    line = Prompt.ask("  [bold cyan]bridge[/]", default="", show_default=False).strip()
                    if not line:
                        break
                    b = parse_bridge(line)
                    if b and b["fingerprint"]:
                        p["bridges"].append(bridge_line(b))
                        ok("added")
                    else:
                        err("invalid bridge line")
            elif v.startswith("d") and v[1:].isdigit() and 1 <= int(v[1:]) <= len(p["bridges"]) and len(p["bridges"]) > 1:
                p["bridges"].pop(int(v[1:]) - 1)
            else:
                continue
            st["obfs4"][name] = p
            save_state(st)
            if ob_write_unit(name, p):
                ob_start(name, p)
        elif c == "6" and p["type"] == "tor":
            run(["systemctl", "kill", "-s", "HUP", ob_unit(name)])
            ok("Tor reloaded – new circuits will be used for new connections")
        elif c == "x":
            ob_delete(name)
            pause()
            return
        pause()


def ob_table():
    st = load_state()
    t = Table(box=box.ROUNDED, border_style="yellow", header_style="bold yellow")
    for c in ["#", "Name", "Type", "Status", "Port", "Details"]:
        t.add_column(c)
    names = sorted(st["obfs4"])
    for i, n in enumerate(names, 1):
        p = st["obfs4"][n]
        s = ob_status(n, p)
        typ = {"tor": "Tor+bridges", "direct": "own server", "server": "SERVER"}[p["type"]]
        if p["type"] == "tor":
            det = f"{len(p['bridges'])} bridge(s)" + (f", HTTP :{p['http_port']}" if p.get("http_port") else "")
        elif p["type"] == "direct":
            det = f"{p['bridge']['host']}:{p['bridge']['port']}" + (f" → ssh tunnel '{p['tunnel']}'" if p.get("behind") == "ssh" else "")
        else:
            det = f"→ {p['target']}"
        t.add_row(str(i), Text(n, style="bold white"), typ,
                  Text("● " + s.upper(), style="bold green" if s == "up" else "bold red" if s == "stopped" else "bold yellow"),
                  Text(f"{p['bind']}:{ob_listen_port(p)}", style="bold cyan"), Text(det, style=DIM))
    return t, names


def obfs4_menu():
    while True:
        header("obfs4 Proxies")
        t, names = ob_table()
        console.print(Align.center(t if names else Text("No obfs4 profiles yet", style="yellow")))
        c = menu_inline([("1", "Tor + obfs4 bridges"), ("2", "Own obfs4 server"), ("3", "Server mode (this PC)"),
                         ("4", "Manage"), ("5", "Start all"), ("6", "Stop all"), ("0", "Back")], color="yellow")
        if c == "0":
            return
        if c == "1":
            ob_create_tor()
        elif c == "2":
            ob_create_direct()
            pause()
        elif c == "3":
            ob_create_server()
        elif c == "4" and names:
            v = ask("Profile # or name", default="1")
            if v in names:
                ob_manage(v)
            elif v.isdigit() and 1 <= int(v) <= len(names):
                ob_manage(names[int(v) - 1])
        elif c in ("5", "6"):
            st = load_state()
            for n in names:
                if c == "5":
                    ob_start(n, st["obfs4"][n])
                else:
                    run(["systemctl", "disable", "--now", ob_unit(n)])
                    ok(f"{n} stopped")
            pause()


# ════════════════════════════════════════════════════════════════════
#  7. Network tools
# ════════════════════════════════════════════════════════════════════

def public_info():
    header("Public IP & Geo")
    with console.status("[bold cyan]Querying ...", spinner="earth"):
        rc, out, _ = run(["curl", "-s", "--max-time", "6", "https://ipinfo.io/json"])
    try:
        d = json.loads(out)
    except ValueError:
        err("Could not reach ipinfo.io")
        return pause()
    g = Table.grid(padding=(0, 2))
    g.add_column(style=f"bold {ACCENT}", justify="right")
    g.add_column(style="bold white")
    for k in ["ip", "hostname", "city", "region", "country", "loc", "org", "timezone"]:
        if d.get(k):
            g.add_row(k.capitalize(), d[k])
    g.add_row("Local IP", local_ip())
    console.print(Align.center(Panel(g, border_style="green", title="[bold green]Public identity[/]", padding=(1, 3))))
    pause()


def stream_cmd(cmd, title):
    console.rule(f"[bold {ACCENT}]{title}[/]  [grey50]Ctrl+C to stop[/]")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            line = line.rstrip()
            st = "white"
            if re.search(r"unreachable|timeout|100% packet loss|\* \* \*|not known|failure", line, re.I):
                st = "red"
            elif re.search(r"bytes from|time=", line):
                st = "green"
            elif line.startswith(("---", "rtt", "round-trip")):
                st = "bold cyan"
            t = Text(line, style=st)
            t.highlight_regex(r"time=[\d.]+ ?ms|[\d.]+ ms", "bold yellow")
            console.print(t)
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        try:
            rest, _ = proc.communicate(timeout=2)
            for line in (rest or "").splitlines():
                console.print(Text(line, style="bold cyan"))
        except Exception:
            proc.kill()
    console.rule()


def ping_tool():
    header("Ping")
    host = ask("Host", default="8.8.8.8")
    cnt = ask_int("Count (0 = continuous)", default=5, lo=0)
    iface = ask("Source interface (empty = auto)", default="")
    cmd = ["ping", host] + (["-c", str(cnt)] if cnt else []) + (["-I", iface] if iface else [])
    stream_cmd(cmd, f"ping {host}")
    pause()


def trace_tool():
    header("Traceroute")
    host = ask("Host", default="1.1.1.1")
    if has("mtr") and confirm("Use mtr report (better)?", True):
        with console.status("[bold cyan]mtr running (10 cycles) ...", spinner="dots"):
            rc, out, _ = run(["mtr", "-r", "-w", "-c", "10", host], timeout=60)
        console.print(Text(out, style="cyan"))
    elif need("traceroute"):
        stream_cmd(["traceroute", "-n", host], f"traceroute {host}")
    pause()


def dns_tool():
    header("DNS Lookup")
    name = ask("Domain / IP", default="google.com")
    server = ask("DNS server (empty = system)", default="")
    t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}", title=f"[bold]{name}[/]")
    t.add_column("Type")
    t.add_column("Answer")
    try:
        ipaddress.ip_address(name)
        types = ["PTR"]
    except ValueError:
        types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
    with console.status("[bold cyan]Resolving ...", spinner="dots"):
        for typ in types:
            if has("dig"):
                cmd = ["dig", "+short", "+time=3"] + ([f"@{server}"] if server else [])
                cmd += ["-x", name] if typ == "PTR" else [name, typ]
                rc, out, _ = run(cmd, timeout=10)
                ans = out.strip()
            else:
                try:
                    ans = "\n".join(sorted({a[4][0] for a in socket.getaddrinfo(name, None)})) if typ == "A" else ""
                except OSError:
                    ans = ""
            if ans:
                t.add_row(Text(typ, style="bold yellow"), Text(ans, style="green"))
    console.print(Align.center(t))
    pause()


def sockets_tool(listening=True):
    header("Listening Ports" if listening else "Active Connections")
    cmd = ["ss", "-Htunp"] + (["-l"] if listening else ["state", "established"])
    rc, out, _ = run(cmd)
    t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}")
    cols = ["Proto", "Local", "Peer", "Process"] if listening else ["Proto", "Local", "Peer", "Process"]
    for c in cols:
        t.add_column(c)
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        proto = p[0]
        if listening:
            local, peer = p[4], p[5] if len(p) > 5 else ""
            proc_s = " ".join(p[6:])
        else:
            local, peer = p[3], p[4]
            proc_s = " ".join(p[5:])
        m = re.findall(r'\("([^"]+)",pid=(\d+)', proc_s)
        proc_txt = ", ".join(f"{n}({pid})" for n, pid in m) or "-"
        t.add_row(Text(proto, style="cyan" if proto == "tcp" else "yellow"), Text(local, style="bold white"),
                  peer, Text(proc_txt, style="green"))
    console.print(Align.center(t))
    pause()


def routes_tool():
    header("Routing Table & DNS")
    rc, out, _ = run(["ip", "-j", "route"])
    t = Table(box=box.ROUNDED, border_style=ACCENT, header_style=f"bold {ACCENT2}", title="[bold]IPv4 routes[/]")
    for c in ["Destination", "Gateway", "Dev", "Proto", "Metric", "Src"]:
        t.add_column(c)
    try:
        for r in json.loads(out or "[]"):
            t.add_row(Text(r.get("dst", ""), style="bold yellow" if r.get("dst") == "default" else "white"),
                      r.get("gateway", "-"), Text(r.get("dev", "-"), style="cyan"), r.get("protocol", "-"),
                      str(r.get("metric", "-")), r.get("prefsrc", "-"))
    except ValueError:
        pass
    console.print(Align.center(t))
    dns = [l for l in read_file("/etc/resolv.conf").splitlines() if l.strip() and not l.startswith("#")]
    console.print(Align.center(Panel("\n".join(dns) or "-", title="[bold]/etc/resolv.conf[/]", border_style="green")))
    pause()


def lan_discovery():
    header("LAN Discovery")
    iface = pick_iface()
    if not iface:
        return
    v4 = [a for a in get_addrs(iface).get(iface, []) if a["family"] == "inet"]
    if not v4:
        err("Interface has no IPv4 address")
        return pause()
    net = ipaddress.ip_interface(f"{v4[0]['local']}/{v4[0]['prefixlen']}").network
    if net.num_addresses > 1024:
        warn(f"{net} is large – scanning the /24 around this host instead")
        net = ipaddress.ip_interface(f"{v4[0]['local']}/24").network
    hosts = [str(h) for h in net.hosts()]
    alive = set()

    def ping1(h):
        if run(["ping", "-c", "1", "-W", "1", "-I", iface, h], timeout=3)[0] == 0:
            alive.add(h)

    with console.status(f"[bold cyan]Sweeping {net} ({len(hosts)} hosts) ...", spinner="dots12"):
        with ThreadPoolExecutor(max_workers=128) as ex:
            list(ex.map(ping1, hosts))
        time.sleep(0.5)
        rc, out, _ = run(["ip", "-j", "neigh", "show", "dev", iface])
    try:
        neigh = {n["dst"]: n for n in json.loads(out or "[]") if n.get("lladdr")}
    except ValueError:
        neigh = {}
    ips = sorted(alive | set(k for k in neigh if "." in k), key=lambda x: ipaddress.ip_address(x))
    t = Table(box=box.ROUNDED, border_style="green", header_style="bold green", title=f"[bold]{net}[/] – {len(ips)} hosts")
    for c in ["IP", "MAC", "Ping", "Hostname"]:
        t.add_column(c)

    def rdns(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""

    with ThreadPoolExecutor(32) as ex:
        names = dict(zip(ips, ex.map(rdns, ips)))
    me = v4[0]["local"]
    for ip in ips:
        mac = neigh.get(ip, {}).get("lladdr", read_file(f"/sys/class/net/{iface}/address") if ip == me else "-")
        t.add_row(Text(ip + ("  (this host)" if ip == me else ""), style="bold white"), Text(mac, style="magenta"),
                  Text("yes" if ip in alive else "no", style="green" if ip in alive else "red"), names.get(ip, ""))
    console.print(Align.center(t))
    pause()


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def port_check():
    header("TCP Port Check")
    host = ask("Host", default="127.0.0.1")
    try:
        ports = parse_ports(ask("Ports (e.g. 22,80,443,8000-8100)", default="21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"))
    except ValueError:
        err("Bad port list")
        return pause()
    if len(ports) > 5000:
        err("Max 5000 ports per check")
        return pause()
    try:
        addr = socket.gethostbyname(host)
    except OSError:
        err("Cannot resolve host")
        return pause()
    opened = []

    def chk(p):
        with socket.socket() as s:
            s.settimeout(1.0)
            if s.connect_ex((addr, p)) == 0:
                opened.append(p)

    with console.status(f"[bold cyan]Checking {len(ports)} ports on {addr} ...", spinner="dots"):
        with ThreadPoolExecutor(200) as ex:
            list(ex.map(chk, ports))
    t = Table(box=box.ROUNDED, border_style="green", header_style="bold green", title=f"[bold]{host} ({addr})[/]")
    t.add_column("Port")
    t.add_column("State")
    t.add_column("Service")
    for p in sorted(opened):
        try:
            svc = socket.getservbyport(p, "tcp")
        except OSError:
            svc = "?"
        t.add_row(str(p), Text("open", style="bold green"), svc)
    console.print(Align.center(t))
    info(f"{len(opened)} open / {len(ports) - len(opened)} closed or filtered")
    pause()


def speed_test():
    header("Download Speed Test")
    url = "https://speed.cloudflare.com/__down?bytes=50000000"
    info("Downloading 50 MB from Cloudflare (Ctrl+C to abort) ...")
    with console.status("[bold cyan]Measuring ...", spinner="dots12"):
        rc, out, _ = run(["curl", "-s", "-o", "/dev/null", "--max-time", "60", "-w",
                          "%{speed_download} %{time_total} %{time_connect}", url], timeout=70)
    try:
        spd, tot, con = map(float, out.split())
        ok(f"Download: [bold green]{spd * 8 / 1e6:.2f} Mbit/s[/]  ({human_rate(spd).strip()})  "
           f"connect {con * 1000:.0f} ms, total {tot:.1f}s")
    except ValueError:
        err("Speed test failed")
    pause()


def tools_menu():
    while True:
        c = menu("Network Tools", [
            ("1", "Public IP & geo", "what the Internet sees"),
            ("2", "Ping", "colored ping with stats"),
            ("3", "Traceroute / mtr", "path to a host"),
            ("4", "DNS lookup", "A, AAAA, MX, NS, TXT, PTR"),
            ("5", "Listening ports", "which programs listen where"),
            ("6", "Active connections", "established TCP/UDP"),
            ("7", "Routing table & DNS", "routes, gateways, resolvers"),
            ("8", "LAN discovery", "ping sweep + ARP table + hostnames"),
            ("9", "TCP port check", "quick connect check of ports"),
            ("s", "Speed test", "download speed via Cloudflare"),
            ("0", "Back", ""),
        ], color="bright_blue")
        if c == "0":
            return
        {"1": public_info, "2": ping_tool, "3": trace_tool, "4": dns_tool, "5": lambda: sockets_tool(True),
         "6": lambda: sockets_tool(False), "7": routes_tool, "8": lan_discovery, "9": port_check,
         "s": speed_test}[c]()


# ════════════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════════════

def restore_everything():
    header("Restore Everything")
    info("Monitor-mode interfaces:")
    restore_all_monitor()
    info("Spoofed MAC addresses:")
    restore_all_macs()
    pause()


def main_menu():
    actions = {
        "1": show_overview, "2": live_all, "3": inspector, "4": packets_menu, "5": ip_manage,
        "6": mac_menu, "7": wireless_menu, "8": tunnels_menu, "o": obfs4_menu, "9": tools_menu, "r": restore_everything,
    }
    while True:
        c = menu("Main Menu", [
            (None, "─ Interfaces ─", None),
            ("1", "Interfaces overview", "all cards, state, MAC, IPs, mode"),
            ("2", "Live traffic monitor", "real-time rates of every card"),
            ("3", "Interface inspector", "full details + live graph of one card"),
            ("4", "Packet capture & analyzer", "sniff / analyze / save pcap per card"),
            ("5", "IP & link management", "add/del IP, DHCP, up/down, MTU, routes"),
            (None, "─ Identity & Wireless ─", None),
            ("6", "MAC address changer", "random / vendor / custom / restore"),
            ("7", "Wireless & monitor mode", "monitor on/off with exact restore, scan"),
            (None, "─ Services ─", None),
            ("8", "SSH tunnel proxies", "SSH to any server → local SOCKS5 on any port"),
            ("o", "obfs4 proxies", "Tor bridges / own obfs4 server → local proxy, or obfs4 server"),
            ("9", "Network tools", "public IP, ping, DNS, ports, LAN scan, speed"),
            ("r", "Restore everything", "undo monitor mode + MAC changes"),
            ("0", "Exit", ""),
        ], subtitle="Main Menu")
        if c == "0":
            console.print(f"\n  [bold {ACCENT}]Bye ✦[/]\n")
            return
        try:
            actions[c]()
        except KeyboardInterrupt:
            console.print()
            warn("Interrupted")
            time.sleep(0.6)
        except Exception as e:  # keep the app alive
            err(f"Unexpected error: {e!r}")
            pause()


def elevate():
    if os.geteuid() != 0:
        script = os.path.realpath(__file__)
        try:
            os.execvp("sudo", ["sudo", "-E", sys.executable, script] + sys.argv[1:])
        except OSError:
            print("NetForge must run as root (sudo).")
            sys.exit(1)


def main():
    ap = argparse.ArgumentParser(prog="netforge", description="NetForge – terminal network toolkit")
    ap.add_argument("--restore", action="store_true", help="restore all monitor-mode cards and MAC addresses, then exit")
    ap.add_argument("--list-proxies", action="store_true", help="print all SSH tunnels and exit")
    ap.add_argument("--obfs4-forward", metavar="NAME", help=argparse.SUPPRESS)
    ap.add_argument("--version", action="version", version=f"NetForge {VERSION}")
    args = ap.parse_args()
    if args.obfs4_forward:
        return obfs4_forward_main(args.obfs4_forward)
    elevate()
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    try:
        if args.restore:
            restore_all_monitor()
            restore_all_macs()
            return
        if args.list_proxies:
            t, _ = tun_table()
            console.print(t)
            return
        main_menu()
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n  [bold {ACCENT}]Bye ✦[/]\n")


if __name__ == "__main__":
    main()
