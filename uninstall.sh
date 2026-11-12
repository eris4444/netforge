#!/usr/bin/env bash
# NetForge uninstaller (restores monitor/MAC, optionally removes all proxies)
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
/usr/local/bin/netforge --restore 2>/dev/null
read -rp "Also delete ALL tunnels, obfs4 profiles, SSH proxies and their users? [y/N] " a
if [[ "$a" =~ ^[Yy]$ ]]; then
  for u in $(systemctl list-units --all --plain --no-legend 'netforge-sshd@*' 'netforge-tunnel-*' 'netforge-obfs4-*' | awk '{print $1}'); do systemctl disable --now "$u"; done
  rm -f /etc/systemd/system/netforge-tunnel-*.service /etc/systemd/system/netforge-obfs4-*.service
  rm -rf /var/lib/netforge-obfs4
  for u in $(getent group netforge | cut -d: -f4 | tr ',' ' '); do pkill -KILL -u "$u"; userdel -f "$u"; done
  for u in $(awk -F: -v g="$(getent group netforge | cut -d: -f3)" '$4==g{print $1}' /etc/passwd); do pkill -KILL -u "$u"; userdel -f "$u"; done
  groupdel netforge 2>/dev/null
  rm -rf /etc/netforge /etc/systemd/system/netforge-sshd@.service /etc/ssh/sshd_config.d/99-netforge.conf /var/lib/netforge
  systemctl daemon-reload
fi
rm -rf /opt/netforge /usr/local/bin/netforge
echo "NetForge removed."
