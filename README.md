<div align="center">

# 🛠️ NetForge

**A colorful terminal network toolkit for Linux (Kali / Debian / Ubuntu)**

SSH proxy manager · Interface inspector · Packet capture · MAC changer · Monitor mode with full restore

</div>

---

## ✨ Features

| Module | What it does |
|---|---|
| **Interfaces overview** | Every card: type, state, MAC, IPv4/IPv6, Wi-Fi mode, driver, gateway & DNS |
| **Live traffic monitor** | Real-time RX/TX rates, packets/s, errors/drops and sparklines for all cards |
| **Interface inspector** | Full details of one card (SSID, signal, channel, permanent MAC, PHY modes) + live graph |
| **Packet capture & analyzer** | Colored live sniffing per card with BPF filters, `.pcap` saving, protocol / top-talker / port statistics |
| **IP & link management** | Add/remove IPs, DHCP renew, up/down, MTU, default route |
| **MAC changer** | Random, same-vendor random, custom, restore original / permanent hardware MAC |
| **Wireless & monitor mode** | Enable/disable monitor mode with **exact state backup & restore**, channel, TX power, injection test, Wi-Fi scan |
| **SSH tunnel proxies** | SSH from this PC to any server and get a local **SOCKS5 proxy (no auth)** on any port. Unlimited tunnels, password / key / auto-installed key auth, auto-reconnect, start on boot, exit-IP & latency test, optional LAN sharing, detection of manual `ssh -D` tunnels |
| **obfs4 proxies** | **Tor + obfs4 bridges** → local SOCKS5 (+ optional HTTP proxy, exit country) with live bootstrap progress · **Own obfs4 server** → local proxy, or an SSH tunnel carried over obfs4 · **obfs4 server mode** to wrap SSH/SOCKS on your own server and print the client connection line |
| **Host SSH server mode** | (advanced) run extra SSH servers on this PC with tunnel-only accounts, expiry dates, sessions, export |
| **Network tools** | Public IP & geo, ping, traceroute/mtr, DNS lookup, listening ports, connections, routes, LAN discovery, TCP port check, speed test |
| **Restore everything** | One key to undo all monitor-mode and MAC changes |

## 📦 Install

```bash
git clone https://github.com/eris4444/netforge.git
cd netforge
sudo ./install.sh
```

Then just run:

```bash
netforge
```

(It re-launches itself with `sudo` when needed.)

### CLI options

```bash
netforge                 # interactive menu
sudo netforge --restore  # restore all monitor-mode cards and MAC addresses
netforge --list-proxies  # print all SSH tunnels
netforge --version
```

## 🧦 SSH tunnel proxies

Menu **8** → **New tunnel**: enter server address, SSH port, username and password (or key).
NetForge runs `ssh -N -D` as a systemd service (`netforge-tunnel-<name>.service`) that reconnects automatically and starts on boot.

```bash
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org   # test
export ALL_PROXY=socks5h://127.0.0.1:1080                      # use in terminal
```

Passwords are stored root-only in `/var/lib/netforge/tunnels/`. Choose *NetForge key* to install an SSH key on the server once and stop storing the password.

## 🧅 obfs4

Menu **o**:

| Mode | You give | You get |
|---|---|---|
| Tor + obfs4 bridges | `obfs4 IP:PORT FINGERPRINT cert=… iat-mode=0` lines (bridges.torproject.org, Telegram @GetBridgesBot) | SOCKS5 on `127.0.0.1:<port>` (+ HTTP proxy) |
| Own obfs4 server | `obfs4 SERVER:PORT cert=… iat-mode=0` | SOCKS/HTTP of the server directly, or an SSH tunnel (menu 8) running over obfs4 |
| Server mode | public port + local target (e.g. `127.0.0.1:22`) | obfs4 listener and the connection line for clients |

Typical setup: run **server mode** on your VPS in front of SSH → on your PC choose **Own obfs4 server → SSH** → local SOCKS5 with traffic disguised by obfs4.

Uses `obfs4proxy` (or `lyrebird`) and `tor`; everything runs as auto-restarting systemd services.

## 🔐 Host SSH server mode

- Each proxy is an independent `sshd` instance (`netforge-sshd@<port>.service`) that starts on boot.
- Proxy users have no shell (`/bin/false`), no TTY, tunnel-only (`ssh -N -D`).
- Proxy users are denied on the main system SSH server via `/etc/ssh/sshd_config.d/99-netforge.conf`.
- Existing system accounts are never modified.
- State is kept in `/var/lib/netforge` (root-only).

Client usage:

```bash
ssh -N -D 1080 -p <port> <user>@<server>
# then use SOCKS5 127.0.0.1:1080
```

## 📡 Monitor mode restore

Before switching, NetForge saves the card's mode, MAC, MTU, up/down state, static IPs and NetworkManager state.
*Soft mode* releases only the selected card from NetworkManager; *aggressive mode* stops NetworkManager and wpa_supplicant (like `airmon-ng check kill`) and restarts them on restore.

## 🗑️ Uninstall

```bash
sudo /opt/netforge/uninstall.sh
```

## ⚠️ Disclaimer

Use only on networks and devices you own or are authorized to test.

## 📄 License

MIT
