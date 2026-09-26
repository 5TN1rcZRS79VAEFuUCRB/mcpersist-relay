#!/usr/bin/env bash
# Installs mcpersist-relay on a fresh Ubuntu/Debian server, as a systemd service with a
# Let's Encrypt certificate. Run as root, after DNS points at this server:
#
#   sudo bash install.sh <relay host> <base domain> <email for Let's Encrypt>
#   e.g. sudo bash install.sh relay.v2.mcpersist.com v2.mcpersist.com you@example.com
#
# Safe to re-run: it rebuilds from the latest main and restarts the service.
set -euo pipefail

RELAY_HOST=${1:?usage: install.sh <relay host> <base domain> <email>}
BASE_DOMAIN=${2:?usage: install.sh <relay host> <base domain> <email>}
EMAIL=${3:?usage: install.sh <relay host> <base domain> <email>}
REPO=https://github.com/5TN1rcZRS79VAEFuUCRB/mcpersist-relay
HOME_DIR=/opt/mcpersist-relay

apt-get update
apt-get install -y build-essential git curl certbot

# Open the relay's ports in the server's own firewall: 25565/tcp players, 25575/udp hosts
# (QUIC), 80/tcp certificate renewals. The cloud provider's firewall needs the same.
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 25565/tcp && ufw allow 25575/udp && ufw allow 80/tcp
fi
if iptables -S INPUT 2>/dev/null | grep -q -- "-j REJECT"; then
    # Oracle Cloud's Ubuntu images reject everything but SSH.
    for rule in "-p tcp --dport 25565" "-p udp --dport 25575" "-p tcp --dport 80"; do
        iptables -C INPUT $rule -j ACCEPT 2>/dev/null || iptables -I INPUT $rule -j ACCEPT
    done
    command -v netfilter-persistent >/dev/null && netfilter-persistent save
fi

# Rust, for building (the relay's dependencies need a newer toolchain than distro packages).
if ! command -v cargo >/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

id -u mcpersist-relay >/dev/null 2>&1 || useradd --system --home "$HOME_DIR" --shell /usr/sbin/nologin mcpersist-relay
mkdir -p "$HOME_DIR"/{certs,data}

cargo install --locked --git "$REPO" --root "$HOME_DIR"

# Certificate for the host the mod connects to. certbot answers on port 80, now and at
# every renewal, so keep that port open.
if [ ! -d "/etc/letsencrypt/live/$RELAY_HOST" ]; then
    certbot certonly --standalone -d "$RELAY_HOST" --non-interactive --agree-tos -m "$EMAIL" --no-eff-email
fi
cat > /etc/letsencrypt/renewal-hooks/deploy/mcpersist-relay.sh <<EOF
#!/bin/sh
# Copies the renewed certificate where the relay can read it, then reloads it live.
set -e
cp /etc/letsencrypt/live/$RELAY_HOST/fullchain.pem $HOME_DIR/certs/fullchain.pem
cp /etc/letsencrypt/live/$RELAY_HOST/privkey.pem $HOME_DIR/certs/privkey.pem
chown mcpersist-relay: $HOME_DIR/certs/*.pem
chmod 600 $HOME_DIR/certs/privkey.pem
curl -fsS -X POST http://127.0.0.1:8080/reload-certs || true
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/mcpersist-relay.sh
/etc/letsencrypt/renewal-hooks/deploy/mcpersist-relay.sh
chown -R mcpersist-relay: "$HOME_DIR"/{certs,data}

cat > /etc/systemd/system/mcpersist-relay.service <<EOF
[Unit]
Description=MCPersist relay
After=network-online.target
Wants=network-online.target

[Service]
User=mcpersist-relay
ExecStart=$HOME_DIR/bin/mcpersist-relay
Environment=QUICLIME_CERT_PATH=$HOME_DIR/certs/fullchain.pem
Environment=QUICLIME_KEY_PATH=$HOME_DIR/certs/privkey.pem
Environment=QUICLIME_BASE_DOMAIN=$BASE_DOMAIN
Environment=QUICLIME_DB_PATH=$HOME_DIR/data/names.sqlite
Environment=QUICLIME_BIND_ADDR_QUIC=0.0.0.0:25575
Environment=QUICLIME_BIND_ADDR_MC=0.0.0.0:25565
Environment=QUICLIME_BIND_ADDR_WEB=127.0.0.1:8080
Environment=RUST_LOG=info
# Binding 25565 as a non-root user.
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now mcpersist-relay
systemctl restart mcpersist-relay
sleep 2
systemctl --no-pager status mcpersist-relay | head -5
curl -fsS http://127.0.0.1:8080/metrics && echo
echo "Relay running. Back up $HOME_DIR/data/names.sqlite: it holds every world's address."
