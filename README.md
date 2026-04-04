# pulse

A zero-config encrypted mesh network in a single binary. Nodes discover each other via gossip, traffic is routed by measured link quality, and the whole thing is managed from the CLI or an interactive TUI.

## What it does

- **Encrypted mesh** between any number of nodes over QUIC (with WebSocket fallback)
- **Layer 3 VPN** via TUN interface — mesh IPs just work like a LAN
- **NAT traversal** — automatic QUIC hole punching for direct peer-to-peer links
- **Multipath routing** — traffic load-balanced across paths scored by latency, loss, and hop count
- **Exit nodes** — forward traffic to the internet through designated nodes
- **Tag-based ACL policies** — `tag:dev` can't reach `tag:prod`, first-match firewall rules
- **DNS** for the `.pulse` TLD — `ssh user@db-server.pulse`
- **SOCKS5 proxy** — transparent mesh routing for any application
- **Network isolation** — separate pulse deployments with `--network` IDs
- **Interactive TUI** (`pulse top`) — k9s-style dashboard for managing the mesh
- **Prometheus metrics** — `/metrics` endpoint for Grafana/alerting

## Architecture

```
                    ┌──────────────┐
                    │   CA Node    │  Signs certificates
                    │  (--ca)      │  Handles join flow
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴────┐ ┌────┴──────┐
        │  Scribe   │ │ Relay  │ │  Client   │
        │ (--scribe)│ │        │ │(--socks   │
        │ ACLs,DNS, │ │forwards│ │ --dns     │
        │ tags,     │ │traffic │ │ --tun)    │
        │ tokens    │ │        │ │           │
        └───────────┘ └────────┘ └───────────┘
```

**Two control roles (can be on the same or different machines):**

- **CA** — certificate authority. Signs node certificates, handles the join flow.
- **Scribe** — network config authority. Manages ACLs, DNS zones, tags, names, revocations, and join tokens. Distributes signed config to all nodes.

Every node is also a **relay** that forwards traffic for other nodes. Roles are composable — a single node can be CA + scribe + relay + exit.

## Quickstart

No config file needed. Everything is flags.

```bash
# Build
go build -o pulse ./cmd/pulse/

# On a server with a public IP — start as CA:
pulse --ca --scribe --addr relay.example.com:443 --listen :443 \
      --network mynet --token $(openssl rand -hex 32)

# On another machine — join the mesh:
pulse join relay.example.com:443 --token <token>

# Start with services enabled:
pulse start --socks --dns --tun --network mynet relay.example.com:443

# Check status:
pulse status
pulse top     # interactive TUI
```

## CLI Reference

### Lifecycle

```
pulse [flags] [peers...]              Start in foreground
pulse start [flags] [peers...]        Start as background daemon
pulse stop                            Graceful shutdown
pulse id                              Print node ID and mesh IP
pulse cert                            Show certificate expiry and status
pulse top                             Interactive TUI dashboard
```

### Mesh

```
pulse join <relay> --token <tok>      Join a mesh (one-time)
pulse status                          Show mesh status table
pulse tag <node-id> <tag>             Add a tag to a node
pulse untag <node-id> <tag>           Remove a tag
pulse name <node-id> <name>           Set a friendly name
pulse revoke --node <id>              Revoke a node's certificate
```

### Policy

```
pulse acl list                        Show ACL rules
pulse acl add --from <pat> --to <pat> Add a rule (--deny, --ports 22,443)
pulse acl remove <index>              Remove a rule by index
```

ACL patterns: node ID globs (`a3f2*`), tags (`tag:prod`), names (`db-server`), or `*`.

Rules are evaluated top-to-bottom, first match wins. No rules = open by default. Adding any rule activates policy mode (unmatched = deny).

### Tokens

```
pulse token                           Show legacy master token (CA only)
pulse token create --ttl 1h           Create a time-limited token
pulse token create --max-uses 1       Create a single-use token
pulse token list                      List all tokens
pulse token revoke <prefix>           Revoke a token
```

### Networking

```
pulse connect --node <id> --dest <addr>   SSH ProxyCommand tunnel
pulse forward --node <id> --dest <addr> --local <addr>   Port forward
pulse dns list|add|remove             Manage DNS records
pulse route list|add|remove           Manage exit routes
```

### Admin

```
pulse ca log                          View CA audit log
pulse ca sign --ca-dir <dir> ...      Offline cert signing
pulse setup dns                       Configure systemd-resolved for .pulse
```

## Node Flags

```
--config <file>        Path to config.toml (optional)
--data-dir <path>      Data directory (default ~/.pulse)
--addr <addr>          Advertised address (default :8443)
--listen <addr>        Bind address (default: same as --addr)
--tcp <addr>           TCP tunnel listener (default :7000)
--network <id>         Network isolation ID
--join <addr>          CA relay address (auto-join on startup)
--token <secret>       Join token
--log-level <level>    debug, info, warn, error (default: info)
```

## Feature Flags

```
--ca                   Certificate authority
--ca-token <secret>    Token the CA accepts (defaults to --token)
--scribe               Control plane (ACLs, DNS, tags, dashboard)
--scribe-listen <addr> Scribe HTTP API (default 127.0.0.1:8080)
--socks                SOCKS5 proxy
--socks-listen <addr>  SOCKS5 address (default 127.0.0.1:1080)
--dns                  DNS server for .pulse TLD
--dns-listen <addr>    DNS address (default 127.0.0.1:5353)
--tun                  TUN interface for layer 3 routing (Linux)
--exit                 Exit node (forwards traffic to internet)
```

## How it works

### Transport

Nodes try QUIC first (no head-of-line blocking, 0-RTT reconnect), fall back to WebSocket+yamux if UDP is blocked. Transport selection is transparent — both return the same `Session` interface.

### Gossip

Every 10 seconds, each node sends its full peer table to all directly connected neighbors. Entries propagate with incrementing hop counts. Stale entries (not seen in 5 minutes) are pruned. Max hop count: 16.

### Routing

The router scores each path using:

```
score = latency_ms * (1 + 5*loss_rate) * (1 + 0.3*hop_count)
```

A 2-hop path at 5ms beats a 1-hop path at 200ms. When multiple viable paths exist, traffic is load-balanced across all of them (multipath).

### NAT Traversal

Nodes discover their public address via `/whoami` on a relay, then coordinate simultaneous UDP punches to establish direct QUIC links. The relay remains as fallback.

### TUN (Layer 3 VPN)

Each node gets a deterministic mesh IP (`10.100.x.x`) derived from its node ID. The `pulse0` TUN interface handles routing at the kernel level. Exit node CIDRs are auto-learned from gossip and installed as kernel routes.

### Certificate Lifecycle

- CA cert: 10 years
- Node certs: 90 days, auto-renewed when <30 days remain
- Renewal happens through the mesh (re-join flow) — no downtime
- TLS configs use dynamic callbacks — renewed certs are picked up without restart

### Security

- **mTLS** between all peers using CA-signed ed25519 certificates
- **Constant-time** token comparison (timing attack resistant)
- **Peer identity verification** — nodeID must match SHA256 of public key
- **ACL enforcement at every hop** — not just the terminating relay
- **Signed network config** — ACLs, DNS, tags distributed via ed25519-signed NetworkConfig from the scribe
- **SSRF protection** — tunnel DestAddr validated, cloud metadata IPs blocked
- **Network isolation** — `--network` ID checked in handshake, mismatched peers rejected
- **Audit log** — all CA operations (join attempts, cert issuance, revocations) logged with fsync

## HTTP API

The scribe exposes a REST API (default `127.0.0.1:8080`):

| Endpoint | Methods | Purpose |
|----------|---------|---------|
| `GET /api/status` | GET | Full mesh state |
| `GET /api/nodes` | GET | Peer list |
| `GET/PUT /api/config` | GET, PUT | Raw NetworkConfig |
| `GET/POST/DELETE /api/dns` | * | DNS zone CRUD |
| `GET/POST/DELETE /api/acls` | * | ACL rule CRUD |
| `POST/DELETE /api/tags` | * | Node tag management |
| `PUT /api/name` | PUT | Set node name |
| `GET /api/routes` | GET | Exit route table |
| `POST /api/revoke` | POST | Revoke a node |
| `GET/POST/DELETE /api/tokens` | * | Token management |
| `GET /metrics` | GET | Prometheus metrics |

## Prometheus Metrics

```
pulse_peers_total                      # known peers
pulse_peers_connected                  # peers with active sessions
pulse_peer_latency_ms{node_id,name}    # per-peer RTT
pulse_peer_loss_ratio{node_id,name}    # per-peer packet loss
pulse_cert_expiry_seconds              # seconds until cert expires
pulse_acl_rules_total                  # ACL rule count
pulse_tokens_valid                     # usable join tokens
pulse_node_info{node_id,network_id}    # node metadata labels
```

## Config File (optional)

All settings can be passed as flags. A TOML config file is optional:

```toml
[node]
addr       = "relay.example.com:443"
listen     = ":443"
network_id = "prod"
log_level  = "info"

[ca]
enabled    = true
join_token = "your-secret-token"

[scribe]
enabled = true

[tun]
enabled = true

[socks]
enabled = true

[dns]
enabled = true
listen  = "127.0.0.1:5353"
```

## Examples

### Home + relay setup

```bash
# Remote server (CA + relay):
pulse --ca --addr relay.example.com:443 --listen :443 \
      --network home --token $(openssl rand -hex 32)

# Home machine (scribe + all services):
pulse join relay.example.com:443 --token <token>
pulse start --scribe --socks --dns --tun --network home relay.example.com:443

# Name your nodes:
pulse name <relay-id> relay-01
pulse name <home-id> home-desktop
pulse tag <relay-id> infra
```

### SSH through the mesh

```bash
# Direct (with TUN enabled):
ssh user@10.100.247.82

# Via DNS:
ssh user@relay-01.pulse

# Via ProxyCommand (no TUN needed):
ssh -o ProxyCommand="pulse connect --node <id> --dest localhost:22" user@relay
```

### Access control

```bash
# Allow infra nodes SSH everywhere:
pulse acl add --from "tag:infra" --to "*" --ports 22

# Block dev from prod:
pulse acl add --from "tag:dev" --to "tag:prod" --deny

# Allow DB access on postgres port only:
pulse acl add --from "*" --to "tag:db" --ports 5432
```

### Time-limited invite

```bash
# Create a 1-hour, single-use token:
pulse token create --ttl 1h --max-uses 1
# Share the token — it self-destructs after one use or one hour
```

## License

MIT
