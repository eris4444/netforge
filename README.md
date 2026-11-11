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
| **SSH proxy manager** | Unlimited SSH tunnel servers on any port with any users/passwords, bulk creation, expiry dates, online sessions, kick, logs, live tunnel test, export list |
| **Network tools** | Public IP & geo, ping, traceroute/mtr, DNS lookup, listening ports, connections, routes, LAN discovery, TCP port check, speed test |
| **Restore everything** | One key to undo all monitor-mode and MAC changes |

## 📦 Install

```bash
git clone https://github.com/<your-username>/netforge.git
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
netforge --list-proxies  # print all SSH proxies
netforge --version
```

## 🔐 SSH proxy design

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
