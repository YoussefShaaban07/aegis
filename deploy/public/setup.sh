#!/usr/bin/env bash
# Put the Aegis demo on the internet: Ubuntu 22.04/24.04 or Debian 12 server, a domain pointing at it.
#
#   curl -fsSL https://raw.githubusercontent.com/YoussefShaaban07/aegis/main/deploy/public/setup.sh | sudo bash -s -- demo.example.com
#
# What it does:
#   * installs Python, git and Caddy (Caddy gets a free HTTPS certificate for your domain automatically);
#   * puts Aegis in /opt/aegis-public, owned by an unprivileged "aegis" user, in a virtual environment;
#   * runs the dashboard on 127.0.0.1:8000 with AEGIS_PUBLIC=1: the simulator's Modbus and EtherNet/IP ports
#     listen on this machine only, and failed logins are counted per visitor;
#   * only ports 80 and 443 are opened to the internet (ufw, if it's installed).
# No AI key is set: the copilot uses the labelled scripted model, so nobody can run up a bill on your key.
# Re-run it any time to update to the latest version from GitHub.
set -euo pipefail
DOMAIN="${1:?usage: setup.sh your.domain.name}"
REPO="${AEGIS_REPO:-https://github.com/YoussefShaaban07/aegis.git}"
DIR=/opt/aegis-public

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip git curl debian-keyring debian-archive-keyring apt-transport-https gnupg
if ! command -v caddy >/dev/null; then
  if ! apt-get install -y -q caddy 2>/dev/null; then          # older releases: Caddy's own repository
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -q && apt-get install -y -q caddy
  fi
fi

id aegis >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin aegis
if [ -d "$DIR/.git" ]; then
  sudo -u aegis git -C "$DIR" fetch -q origin && sudo -u aegis git -C "$DIR" reset -q --hard origin/main
else
  mkdir -p "$DIR" && chown aegis: "$DIR"
  sudo -u aegis git clone -q "$REPO" "$DIR"
fi
sudo -u aegis python3 -m venv "$DIR/.venv"
sudo -u aegis "$DIR/.venv/bin/pip" install -q --upgrade pip
sudo -u aegis "$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"

if [ ! -f "$DIR/.env" ]; then
  cat > "$DIR/.env" <<ENV
AEGIS_DEMO=1
AEGIS_PUBLIC=1
AEGIS_HTTPS=1
AEGIS_HOST=127.0.0.1
PORT=8000
AEGIS_SESSION_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
AEGIS_AUDIT_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
ENV
  chown aegis: "$DIR/.env" && chmod 600 "$DIR/.env"
fi

install -m 644 "$DIR/deploy/public/aegis-demo.service" /etc/systemd/system/aegis-demo.service
sed "s/DOMAIN_NAME/$DOMAIN/" "$DIR/deploy/public/Caddyfile" > /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable -q --now aegis-demo
systemctl restart aegis-demo
systemctl reload caddy || systemctl restart caddy

if command -v ufw >/dev/null; then ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; fi
sleep 4
if curl -fs -o /dev/null http://127.0.0.1:8000/; then
  echo "Aegis is running. Open https://$DOMAIN (the certificate can take a minute the first time)."
else
  echo "Aegis didn't answer on 127.0.0.1:8000. See: journalctl -u aegis-demo -n 50"
  exit 1
fi
