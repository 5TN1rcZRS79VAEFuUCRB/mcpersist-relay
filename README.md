# mcpersist-relay

The relay behind [MCPersist](https://github.com/5TN1rcZRS79VAEFuUCRB/MCPersist) v2: a fork of
[e4mc-quiclime](https://github.com/vgskye/e4mc-quiclime), the relay e4mc uses to put LAN worlds on the
internet.

The difference from upstream: a host may send a secret **world key** with its domain request, and the
relay gives that key the same `word-word.<base domain>` name every time, including across relay restarts.
Hosts without a key get a random name, as with e4mc. Only one live session can hold a name at a time.

## Running

Configured by environment variables:

| Variable | Meaning |
|---|---|
| `QUICLIME_CERT_PATH`, `QUICLIME_KEY_PATH` | TLS certificate and key (PEM) for the QUIC endpoint |
| `QUICLIME_BASE_DOMAIN` | Names are issued under this domain; point a wildcard DNS record for it at the relay |
| `QUICLIME_DB_PATH` | SQLite file holding key → name assignments. Back it up: losing it changes every world's address |
| `QUICLIME_BIND_ADDR_QUIC` | UDP address for host connections (e4mc uses port 25575) |
| `QUICLIME_BIND_ADDR_MC` | TCP address for players, normally `0.0.0.0:25565` |
| `QUICLIME_BIND_ADDR_VOICE` | Optional, default `0.0.0.0:24454`. UDP address for players' Simple Voice Chat traffic, which goes to their world's host over its QUIC connection |
| `QUICLIME_STARTUP_GRACE_SECS` | Optional, default 25. How long a joining player waits for an offline persistent world to come back, e.g. while it restarts in the background after its host left. Keep it under the Minecraft client's 30-second timeout |
| `QUICLIME_BIND_ADDR_WEB` | HTTP control endpoints (metrics, broadcast, stop, cert reload, Dialtone tickets). They have no authentication, so the relay refuses to start unless this is a loopback address such as `127.0.0.1:8080`. If Dialtone is enabled later, expose only `/.well-known/dialtone_ticket/` through a reverse proxy |

A name unused for 90 days is freed; a world that is online is never freed, however long ago it registered.
Players arriving through a Minecraft Transfer packet (1.20.5+) are routed like normal logins. A player joining a persistent world that is offline waits up to the startup grace period for it to come back; server-list pings for it say it is starting up.

The database stores only a hash of each world key and the name's label, not the base domain, so moving
the relay to a new base domain keeps every world's label.

## Deploying

On a fresh Ubuntu or Debian server, once DNS for the relay host and a wildcard for the base domain point
at it, and the provider's firewall allows 25565/tcp, 25575/udp, 24454/udp and 80/tcp:

```
curl -fsSLO https://raw.githubusercontent.com/5TN1rcZRS79VAEFuUCRB/mcpersist-relay/main/deploy/install.sh
sudo bash install.sh relay.mcpersist.com mcpersist.com you@example.com
```

It opens those ports in the server's own firewall, builds the relay, gets a Let's Encrypt certificate for
the relay host (renewals reload it live), and runs it as the `mcpersist-relay` systemd service. Re-running
it updates to the latest `main`.

Each region is its own relay with its own base domain, e.g. `install.sh relay.eu.mcpersist.com
eu.mcpersist.com ...`; the mod lists the regions and hosts through the nearest. List every region's iroh
relay in `/var/www/mcpersist/relaymap.json` on the server behind the mod's relay map URL.

## Protocol change

`{"kind": "request_domain_assignment", "key": "<16–256 chars>"}`. `key` is optional. When a key can't be
served, the relay replies `{"kind": "domain_assignment_failed", "reason": "name_in_use" | "invalid_key" |
"internal"}` and closes the connection.

Voice: `probe_capabilities` lists `"voice"` and gives `voice_port`, the UDP port players send Simple
Voice Chat packets to. A host sends `{"kind": "voice_register_player", "uuid": "<uuid>"}` for each
player using voice through the relay; that player's packets (which start with `0xFF` and their UUID)
then reach the host as QUIC datagrams, prefixed with the player's address (16-byte IPv6, IPv4 mapped,
then a 2-byte port). The host replies with datagrams in the same form, and the relay sends them only to
addresses that have sent voice for that host.

## Tests

`cargo test` runs the relay in-process against a fake host (QUIC) and fake players (TCP).

## License

MIT OR Apache-2.0, as upstream.
