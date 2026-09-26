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
| `QUICLIME_BIND_ADDR_WEB` | HTTP control endpoints (metrics, broadcast, stop, cert reload, Dialtone tickets). They have no authentication, so the relay refuses to start unless this is a loopback address such as `127.0.0.1:8080`. If Dialtone is enabled later, expose only `/.well-known/dialtone_ticket/` through a reverse proxy |

A name unused for 90 days is freed; a world that is online is never freed, however long ago it registered.
Players arriving through a Minecraft Transfer packet (1.20.5+) are routed like normal logins.

The database stores only a hash of each world key and the name's label, not the base domain, so moving
the relay to a new base domain keeps every world's label.

## Protocol change

`{"kind": "request_domain_assignment", "key": "<16–256 chars>"}`. `key` is optional. When a key can't be
served, the relay replies `{"kind": "domain_assignment_failed", "reason": "name_in_use" | "invalid_key" |
"internal"}` and closes the connection.

## Tests

`cargo test` runs the relay in-process against a fake host (QUIC) and fake players (TCP).

## License

MIT OR Apache-2.0, as upstream.
