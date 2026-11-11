#!/usr/bin/env bash
# NetForge installer
set -e
C='\033[1;36m'; G='\033[1;32m'; R='\033[1;31m'; N='\033[0m'
[ "$(id -u)" -eq 0 ] || { echo -e "${R}Run with sudo:${N} sudo ./install.sh"; exit 1; }
DIR="$(cd "$(dirname "$0")" && pwd)"
echo -e "${C}[*] Installing dependencies...${N}"
PKGS="python3 python3-rich iproute2 iw ethtool tcpdump openssh-server openssh-client curl dnsutils traceroute iputils-ping"
MISSING=""
for p in $PKGS; do dpkg -s "$p" >/dev/null 2>&1 || MISSING="$MISSING $p"; done
if [ -n "$MISSING" ]; then apt-get update -qq && apt-get install -y $MISSING; fi
echo -e "${C}[*] Copying files...${N}"
install -d -m 755 /opt/netforge
install -m 755 "$DIR/netforge.py" /opt/netforge/netforge.py
install -m 755 "$DIR/uninstall.sh" /opt/netforge/uninstall.sh
ln -sf /opt/netforge/netforge.py /usr/local/bin/netforge
install -d -m 700 /var/lib/netforge
echo -e "${G}[✔] NetForge installed. Run:  ${C}netforge${N}"
