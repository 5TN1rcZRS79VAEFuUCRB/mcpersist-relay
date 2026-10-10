#!/usr/bin/env bash
# Installs mcpersist-relay on a fresh Ubuntu/Debian server, as a systemd service with a
# Let's Encrypt certificate. Run as root, after DNS points at this server:
#
#   sudo bash install.sh <relay host> <base domain> <email for Let's Encrypt, or none> [homepage URL]
#   e.g. sudo bash install.sh relay.mcpersist.com mcpersist.com you@example.com https://example.com
#
# Besides the relay it sets up, for modded players' peer-to-peer connections:
# - an iroh relay at https://<relay host>:8443 (plus UDP 7842), using the same certificate;
# - Caddy on https://<base domain>, serving the relay list (/relaymap.json) and the Dialtone
#   ticket lookup, and redirecting everything else to the homepage URL if given.
# DNS: <base domain> and *.<base domain> point here, and *.<base domain> has the TXT record
# e4mc-dialtone-resolver=<base domain>.
#
# Safe to re-run: it rebuilds from the latest main and restarts the service.
set -euo pipefail

RELAY_HOST=${1:?usage: install.sh <relay host> <base domain> <email>}
BASE_DOMAIN=${2:?usage: install.sh <relay host> <base domain> <email>}
EMAIL=${3:?usage: install.sh <relay host> <base domain> <email>}
HOMEPAGE=${4:-}
REPO=https://github.com/5TN1rcZRS79VAEFuUCRB/mcpersist-relay
HOME_DIR=/opt/mcpersist-relay

apt-get update
apt-get install -y build-essential git curl certbot caddy

# Open the relay's ports in the server's own firewall: 25565/tcp players, 25575/udp hosts
# (QUIC), 24454/udp players' Simple Voice Chat, 80/tcp certificate renewals, 443/tcp ticket lookups, 8443/tcp and 7842/udp the
# iroh relay. The cloud provider's firewall needs the same.
PORTS="25565/tcp 25575/udp 24454/udp 80/tcp 443/tcp 8443/tcp 7842/udp"
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    for port in $PORTS; do ufw allow "$port"; done
fi
if iptables -S INPUT 2>/dev/null | grep -q -- "-j REJECT"; then
    # Oracle Cloud's Ubuntu images reject everything but SSH.
    for port in $PORTS; do
        rule="-p ${port#*/} --dport ${port%/*}"
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

# cargo install builds under $TMPDIR; Ubuntu 26.04's /tmp is a RAM disk too small for it.
export TMPDIR=/var/tmp
cargo install --locked --git "$REPO" --root "$HOME_DIR"
cargo install --locked iroh-relay --version "^1" --features server --root "$HOME_DIR"

# Certificate for the host the mod connects to. certbot answers on port 80, now and at
# every renewal, so keep that port open.
if [ ! -d "/etc/letsencrypt/live/$RELAY_HOST" ]; then
    if [ "$EMAIL" = none ]; then contact=--register-unsafely-without-email; else contact="-m $EMAIL --no-eff-email"; fi
    # The caddy package starts Caddy on port 80 with its default site; it's configured below.
    systemctl stop caddy
    certbot certonly --standalone -d "$RELAY_HOST" --non-interactive --agree-tos $contact
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
Environment=QUICLIME_BIND_ADDR_VOICE=0.0.0.0:24454
Environment=QUICLIME_BIND_ADDR_WEB=127.0.0.1:8080
Environment=RUST_LOG=info
# Binding 25565 as a non-root user.
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
# The iroh relay modded players connect peer-to-peer through. Its plain-HTTP side only
# serves a captive-portal check, so it stays off port 80 (certbot's) and loopback-only.
cat > "$HOME_DIR/iroh-relay.toml" <<EOF
http_bind_addr = "127.0.0.1:3340"
enable_quic_addr_discovery = true
enable_metrics = false

[tls]
https_bind_addr = "[::]:8443"
quic_bind_addr = "[::]:7842"
cert_mode = "Reloading"
manual_cert_path = "$HOME_DIR/certs/fullchain.pem"
manual_key_path = "$HOME_DIR/certs/privkey.pem"
EOF
cat > /etc/systemd/system/mcpersist-iroh-relay.service <<EOF
[Unit]
Description=MCPersist iroh relay (peer-to-peer connections)
After=network-online.target
Wants=network-online.target

[Service]
User=mcpersist-relay
ExecStart=$HOME_DIR/bin/iroh-relay --config-path $HOME_DIR/iroh-relay.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# The public face of the base domain: the relay list, ticket lookups and a mirror of iroh-java's
# native libraries (put in /var/www/mcpersist/natives by hand). The relay's other web endpoints
# (/reload-certs, /stop, ...) stay on loopback.
if [ -n "$HOMEPAGE" ]; then fallback="redir $HOMEPAGE"; else fallback="respond 404"; fi
mkdir -p /var/www/mcpersist
# The how-to-join page, which servers requiring the mod send players without it to.
mkdir -p /var/www/mcpersist/join
cp "$(dirname "$0")/join.html" /var/www/mcpersist/join/index.html
# Every region's iroh relay goes in this list, so it's only written the first time: add the others by hand.
[ -f /var/www/mcpersist/relaymap.json ] || echo "[\"https://$RELAY_HOST:8443\"]" > /var/www/mcpersist/relaymap.json
cat > /etc/caddy/Caddyfile <<EOF
{
	auto_https disable_redirects
}

https://$BASE_DOMAIN {
	tls {
		# Port 80 is certbot's, for the relay certificate.
		issuer acme {
			disable_http_challenge
		}
	}
	handle /.well-known/dialtone_ticket/* {
		reverse_proxy 127.0.0.1:8080
	}
	@static path /relaymap.json /latest.json /natives/* /join /join/*
	handle @static {
		root * /var/www/mcpersist
		file_server
	}
	handle {
		$fallback
	}
}
EOF

# The newest MCPersist release, for the mod to tell hosts when theirs is outdated: refreshed hourly
# from GitHub, so a release needs nothing else.
cat > /usr/local/bin/mcpersist-latest <<'LATEST'
#!/usr/bin/env bash
set -euo pipefail
release=$(curl -fsS https://api.github.com/repos/5TN1rcZRS79VAEFuUCRB/MCPersist/releases/latest)
version=$(sed -nE 's/^ *"tag_name": *"v?([0-9A-Za-z.+-]+)",?$/\1/p' <<<"$release" | head -1)
[ -n "$version" ]
printf '{"version":"%s"}\n' "$version" > /var/www/mcpersist/latest.json.tmp
mv /var/www/mcpersist/latest.json.tmp /var/www/mcpersist/latest.json
LATEST
chmod +x /usr/local/bin/mcpersist-latest
echo "7 * * * * root /usr/local/bin/mcpersist-latest 2>&1 | logger -t mcpersist-latest" > /etc/cron.d/mcpersist-latest
/usr/local/bin/mcpersist-latest || true

# Updates itself: every 15 minutes, a newer main whose tests passed on GitHub is built, and the
# relay restarts onto it once no world is hosted here, so an update doesn't disconnect anyone.
# A relay that always has a world online restarts onto it in the 4 a.m. (US Central) hour
# instead; its worlds reconnect on their own, with the same addresses, within seconds.
cat > /usr/local/bin/mcpersist-update <<EOF
#!/usr/bin/env bash
set -euo pipefail
latest=\$(git ls-remote $REPO refs/heads/main | cut -f1)
[ "\$latest" != "\$(cat $HOME_DIR/deployed-commit 2>/dev/null)" ] || exit 0
curl -fsS "https://api.github.com/repos/${REPO#https://github.com/}/commits/\$latest/check-runs" \\
    | grep -E '"conclusion": ?"success"' >/dev/null || exit 0  # Not -q: quitting early fails curl, and pipefail with it.
. /root/.cargo/env
TMPDIR=/var/tmp cargo install --locked --quiet --git $REPO --rev "\$latest" --root $HOME_DIR
[ "\$(curl -fsS http://127.0.0.1:8080/metrics)" = "host_count 0" ] || [ "\$(TZ=America/Chicago date +%H)" = 04 ] || exit 0
systemctl restart mcpersist-relay
echo "\$latest" > $HOME_DIR/deployed-commit
echo "updated to \$latest"
EOF
chmod +x /usr/local/bin/mcpersist-update
echo "*/15 * * * * root flock -n /run/mcpersist-update.lock /usr/local/bin/mcpersist-update 2>&1 | logger -t mcpersist-update" \
    > /etc/cron.d/mcpersist-update
git ls-remote "$REPO" refs/heads/main | cut -f1 > "$HOME_DIR/deployed-commit"

systemctl daemon-reload
systemctl enable --now mcpersist-relay mcpersist-iroh-relay caddy
systemctl restart mcpersist-relay mcpersist-iroh-relay caddy
sleep 2
systemctl --no-pager status mcpersist-relay | head -5
curl -fsS http://127.0.0.1:8080/metrics && echo
systemctl --no-pager status mcpersist-iroh-relay caddy | grep -E "^●|Active:"
echo "Relay running. Back up $HOME_DIR/data/names.sqlite: it holds every world's address."
