#!/bin/sh
# Nöbet Agent kurulumu (systemd'li Linux). Kullanım: sudo ./install.sh <manager-adresi> <ajan-anahtarı>
set -eu
[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın (sudo)." >&2; exit 1; }
[ $# -eq 2 ] || { echo "Kullanım: $0 https://panel.example.com nbt_..." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 gerekli." >&2; exit 1; }
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -d -m 755 /opt/nobet
install -m 755 "$DIR/nobet_agent.py" /opt/nobet/nobet_agent.py
install -d -m 700 /etc/nobet
if [ ! -f /etc/nobet/agent.json ]; then
  umask 077
  cat > /etc/nobet/agent.json <<JSON
{
  "manager": "$1",
  "token": "$2",
  "interval": 30,
  "scan_interval": 300
}
JSON
else
  echo "/etc/nobet/agent.json zaten var; değiştirilmedi."
fi
install -m 644 "$DIR/nobet-agent.service" /etc/systemd/system/nobet-agent.service
systemctl daemon-reload
systemctl enable --now nobet-agent.service
echo "Nöbet Agent kuruldu. Durum: systemctl status nobet-agent"
