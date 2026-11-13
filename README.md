# Trairi

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/AKHYui/Trairi/actions/workflows/ci.yml/badge.svg)](https://github.com/AKHYui/Trairi/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A single-binary reverse proxy and overlay networking tool written in Rust.

> **One executable, no separate client/server binaries.**
> The `mode` field in the config or the CLI subcommand decides whether it runs
> as a server or a client.

```bash
trairi server -c server.yaml     # run as a server
trairi client -c client.yaml     # run as a client
trairi run    -c any.yaml        # role from `mode` in the config
trairi validate -c any.yaml      # validate the config only
trairi version
```

> Configuration is **YAML** (`.yaml` / `.yml`). Because YAML is a superset of
> JSON, a JSON file also parses.

---

## 1. Quick start

Server (public machine):

```yaml
# server.yaml
mode: server

server:
  bind_port: 7000
  vhost_http_port: 8080
  token: "replace-with-a-long-random-string"
  # Ports clients may request; an empty value forbids fixed ports
  allow_ports: "7001-7200"
  # Recommended for public deployments
  force_encryption: true

dashboard:
  # Bind to localhost by default; use an SSH tunnel instead of exposing it
  bind_addr: 127.0.0.1
  port: 7500
  user: admin
  password: "replace-with-a-strong-password"
```

```bash
trairi server -c server.yaml
```

Client (internal machine):

```yaml
# client.yaml
mode: client

client:
  server_addr: your.public.ip
  server_port: 7000
  token: "same-token-as-the-server"
  use_encryption: true

proxies:
  - name: ssh
    type: tcp
    local_addr: 127.0.0.1:22
    remote_port: 7001
```

```bash
trairi client -c client.yaml
# then: ssh -p 7001 your.public.ip
```

View the dashboard (an SSH tunnel is strongly recommended; do not expose port
7500 directly to the Internet):

```bash
ssh -L 7500:127.0.0.1:7500 your-server
# then open http://127.0.0.1:7500 locally
```

---

## 2. Feature overview

| Feature | Status | Notes |
|---|---|---|
| TCP proxy | ✅ | `type = "tcp"` |
| UDP proxy | ✅ | `type = "udp"` |
| HTTP virtual host (by domain) | ✅ | `type = "http"` + `custom_domains` / `subdomain` |
| HTTPS virtual host (by SNI) | ✅ | `type = "https"`, **TLS is passed through end-to-end** |
| Secret-key TCP access | ✅ | `type = "stcp"`; no public listener, `sk` authentication |
| P2P proxy | ✅ | `type = "p2p"`; direct KCP + smux path between owner and visitor, fallback to relay |
| Visitor | ✅ | `visitors` list |
| SOCKS5 plugin | ✅ | `type = "socks5"`, built in |
| HTTP proxy plugin | ✅ | `type = "http_proxy"` (CONNECT tunnels) |
| Static file plugin | ✅ | `type = "static_file"` with Basic Auth |
| Multiplexing (smux) | ✅ | One connection carries all proxies |
| tcp/tls/ws/wss/kcp transports | ✅ | TCP auto-sniffing on `bind_port`; KCP uses UDP on the same port |
| Connection encryption (AEAD) | ✅ | ChaCha20-Poly1305 + HKDF |
| Stream compression | ✅ | snappy |
| Token authentication | ✅ | HMAC-SHA256 over the complete Hello, with replay protection |
| Heartbeat / timeout eviction | ✅ | Bidirectional heartbeats |
| Proxy health checks | ✅ | `health_check_type = tcp/http`; status reported to the server |
| Load balancing (group) | ✅ | Same `group` + `group_key` + `remote_port`, round-robin over healthy members |
| Bandwidth limits | ✅ | `bandwidth_limit = "5MB"`, server- or client-side |
| PROXY protocol v1/v2 | ✅ | `proxy_protocol_version = "v1"` |
| Port allowlist | ✅ | `allow_ports = "7001-7200"` |
| Dashboard + JSON API | ✅ | Built in, no frontend build step |
| Client management API | ✅ | `webServer` (`reload` / `stop`) |

Not implemented: QUIC, generic TCP multiplexing outside smux, and Prometheus
metrics. The dashboard JSON API can be scraped if you need metrics.

KCP is a reliable-UDP transport, not an encryption layer. Keep
`force_encryption` / `use_encryption` enabled so the Trairi token and
ChaCha20-Poly1305 record layer still protect the stream. `server.kcp` is
opt-in because it shares UDP `bind_port` with the overlay data plane.

---

## 3. Architecture

```
   ┌──────────── client (private network) ─────────┐        ┌──────── server (public) ────────┐
   │                                               │        │                                 │
   │  local:22 ─┐                                  │        │   :7001  ──┐                    │
   │  local:80 ─┼─ proxy runtime ─ smux session ───┼── TCP ─┼─ :8080(vhost) ── routing ── listen│
   │  plugin:xx ┘   (encryption/compression)       │  TLS   │   :8443(vhost)                  │
   │                                               │  WS    │                                 │
   └───────────────────────────────────────────────┘  WSS   └─────────────────────────────────┘
```

### Connection setup

1. **Transport**: the client connects to the server's `bind_port`. TCP, TLS and
   WebSocket are auto-sniffed; KCP uses UDP on the same port. Sniffing runs in a
   per-connection task, and the first-byte, TLS, and WebSocket handshakes all
   have 5-second timeouts; one slow client cannot block the accept loop.
2. **Plaintext handshake (protocol v2)**: the client sends
   `HelloRequest{salt, timestamp, HMAC(token, full handshake fields), flags}`.
   The server checks the clock window, the HMAC, and a `(salt, timestamp)`
   replay cache.
3. **Key derivation**: `HKDF-SHA256(token, salt)`, then the connection uses
   ChaCha20-Poly1305 record frames. The two directions use different nonce
   direction prefixes, so the same key and counter are never reused in both
   directions.
4. **Multiplexing**: a `smux` session runs on top of the record layer; the first
   stream is the **control stream**.
5. **Login**: `Login{run_id, hostname, os, arch}` → `LoginResp`.
6. **Proxy registration**: `NewProxy` → `NewProxyResp{remote_addr}`.
7. **Forwarding**:
   - the server accepts an external connection and sends `ReqWorkConn` on the
     control stream;
   - the client opens a new smux stream, sends
     `StreamHeader::Work{proxy_name}`, then connects to the local service;
   - both sides copy bytes until EOF (the server may prepend a PROXY protocol
     header).

Control messages use a 4-byte big-endian length prefix + JSON; the data plane
is a plain byte-stream copy.

---

## 4. Configuration reference

The config is YAML. Top-level keys:

```yaml
mode: client        # or server
log: { ... }
server: { ... }     # server parameters
client: { ... }     # client parameters
dashboard: { ... }  # server dashboard
webServer: { ... }  # client management API
proxies:            # proxy definitions
  - name: ...
visitors:           # visitor definitions
  - name: ...
```

### Top level

| Key | Description |
|---|---|
| `mode` | `"server"` or `"client"`; can be overridden on the CLI |
| `log` | `level` (trace/debug/info/warn/error), `file` (empty = console only; a path enables daily rotation), `max_days` (retention in days) |
| `server` | Server parameters |
| `client` | Client parameters |
| `dashboard` | Server dashboard |
| `webServer` | Client management API |
| `proxies` | Proxy definitions (client side) |
| `visitors` | Visitor definitions (client side) |

### `server`

| Key | Default | Description |
|---|---|---|
| `bind_addr` | `0.0.0.0` | Listen address |
| `bind_port` | — | Client control port (required); KCP uses UDP on the same port |
| `kcp` | `false` | Enable KCP (reliable UDP) on `bind_port`; must not collide with `overlay.udp_port` |
| `p2p_port` | `0` | UDP rendezvous port for P2P; 0 = P2P disabled |
| `vhost_http_port` | `0` | HTTP virtual-host port; 0 disables |
| `vhost_https_port` | `0` | HTTPS virtual-host port (SNI routing); 0 disables |
| `subdomain_host` | `""` | Wildcard suffix, e.g. `example.com` |
| `allow_ports` | `""` | Ports clients may request, e.g. `"7001-7200,8000"`; empty forbids fixed ports |
| `max_ports_per_client` | `64` | Port quota per client; 0 = unlimited |
| `authentication_timeout` | `10` | Authentication timeout in seconds |
| `heartbeat_timeout` | `90` | Heartbeat timeout in seconds |
| `max_clients` | `1024` | Maximum clients; 0 = unlimited |
| `token` | `""` | Authentication secret; **required in server mode** |
| `force_encryption` | `true` | Require encryption |
| `tls_cert_file` / `tls_key_file` | `""` | Server TLS certificate/key (PEM) |
| `proxy_protocol_version` | `""` | Default PROXY protocol version for proxies (per-proxy overrides) |

### `client`

| Key | Default | Description |
|---|---|---|
| `server_addr` / `server_port` | — | Server address (required) |
| `token` | `""` | Must match the server |
| `run_id` | auto | Client identity; a new login with the same ID evicts the old one |
| `user` | `""` | Free-form note |
| `protocol` | `tcp` | `tcp` / `tls` / `ws` / `wss` / `kcp` |
| `tls_enable` | `false` | Alias for `protocol = "tls"` |
| `tls_server_name` | `server_addr` | Name used for TLS verification |
| `tls_cert_file` | `""` | Custom CA |
| `tls_insecure` | `false` | Skip certificate verification |
| `ws_path` | `/~!trairi` | WebSocket path |
| `use_encryption` | `true` | Encrypt the record layer (requires a token) |
| `use_compression` | `false` | snappy compression |
| `heartbeat_interval` | `30` | Heartbeat interval in seconds (0 = use the server's suggestion) |
| `p2p_udp_port` | `0` | Local P2P UDP bind port; 0 = random |
| `heartbeat_timeout` | `90` | Heartbeat timeout in seconds |
| `dial_timeout` | `10` | Connect timeout for the server/local service |
| `proxy_protocol_version` | `""` | Default PROXY protocol version |
| `bandwidth_limit` | `""` | Global bandwidth limit (default for proxies) |
| `start` | `[]` | Start only the listed proxies |

### `proxies`

| Key | Description |
|---|---|
| `name` | Required, globally unique |
| `type` | `tcp` / `udp` / `http` / `https` / `stcp` / `p2p` / `socks5` / `http_proxy` / `static_file` |
| `local_addr` | Local service `IP:PORT` (plugins may leave it empty) |
| `local_path` | Root directory for `static_file` |
| `remote_port` | Public TCP/UDP port; 0 = allocate from `allow_ports` |
| `custom_domains` | Domains for HTTP/HTTPS proxies |
| `subdomain` | Used with the server's `subdomain_host` |
| `sk` | Secret key for `stcp` / `p2p` |
| `group` / `group_key` | Load-balancing group (same group + port share a listener) |
| `weight` | Load-balancing weight for group members (1–1000, default 1) |
| `bandwidth_limit` | e.g. `"5MB"`, `"512KB"`; empty = unlimited |
| `bandwidth_limit_mode` | `server` (default) or `client` |
| `proxy_protocol_version` | `""` / `v1` / `v2` |
| `http_user` / `http_pwd` | Basic Auth for `static_file` |
| `health_check_type` | `tcp` / `http`; empty = disabled |
| `health_check_path` | HTTP health-check path (default `/`) |
| `health_check_interval` / `_timeout` / `_max_failed` | Check interval, timeout, consecutive-failure threshold |

### `visitors`

| Key | Description |
|---|---|
| `name` | Required |
| `type` | `stcp` or `p2p` |
| `server_name` | Target proxy name |
| `sk` | Must match the target proxy |
| `bind_addr` / `bind_port` | Local listener |
| `p2p_fallback` | `true` (default): fall back to the server relay when direct P2P fails |

### P2P proxy

P2P needs a server UDP rendezvous port:

```yaml
server:
  p2p_port: 7001       # open UDP 7001; 0 = disabled
```

Owner client:

```yaml
proxies:
  - name: p2p-ssh
    type: p2p
    local_addr: 127.0.0.1:22
    sk: a-shared-secret
```

Visitor client (runs the Trairi agent and a local listener):

```yaml
visitors:
  - name: p2p-ssh-visitor
    type: p2p
    server_name: p2p-ssh
    sk: a-shared-secret
    bind_addr: 127.0.0.1
    bind_port: 2222
    p2p_fallback: true
```

The server only exchanges endpoints. The owner and visitor punch UDP and use
KCP + smux for a direct encrypted path; same-LAN peers try their private
endpoints first, then the public endpoints. If punching fails, the visitor
falls back to the normal server relay. The `sk` is used for HMAC authentication
and to derive the P2P record-layer key.

P2P works best when at least one side has a reachable/public UDP endpoint.
Symmetric NAT or a UDP-blocking firewall may force relay fallback. One KCP
session is shared by multiple visitor TCP connections via smux.

---

## 5. Dashboard and management API

**Server dashboard** at `http://host:7500/`: clients, proxies, connection counts,
and traffic; refreshes every 2 seconds. JSON: `GET /api/overview`; health:
`GET /healthz`. Basic Auth is supported.

**Client management API** (`webServer`):

| Endpoint | Purpose |
|---|---|
| `GET /api/status` | Connection state, registered proxies, public address |
| `GET /api/reload` | Reload the config and reconnect |
| `GET /api/stop` | Exit the process |

---

## 6. Build

You need a Rust toolchain. For static Linux builds, `cargo-zigbuild` + Zig is
recommended.

```bash
# Windows
cargo build --release

# Linux x86_64 static (runs on any Linux)
cargo zigbuild --release --target x86_64-unknown-linux-musl

# Linux x86_64 glibc >= 2.17
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17

# Linux ARM64
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

Artifacts are under `target/<target>/release/trairi` (or `trairi.exe` on Windows).

---

## 7. Tests

```bash
cargo test
cargo clippy --all-targets
```

Current test suite: 79 unit tests, 17 port-forwarding end-to-end tests, and
8 overlay integration tests.

The integration tests start a real server + client in one process and cover:

- TCP forwarding, encrypted channels, WebSocket transport
- HTTP virtual-host routing and unmatched-domain 404s
- UDP forwarding
- Built-in SOCKS5
- secret-key TCP + visitor, wrong `sk` rejection
- PROXY protocol v1 reaching the backend
- Dashboard `/api/overview` with authentication
- Group load balancing
- Wrong token rejection, Hello replay rejection, and slow-client isolation

---

## 8. Security

### 8.1 Code-level defaults (built into this version)

1. **Server mode requires `server.token`**; `trairi server` refuses to start
   otherwise.
2. The Hello HMAC covers every handshake field (version, salt, timestamp,
   encryption/compression flags, client identifier). The server also keeps a
   `(salt, timestamp)` replay cache. `force_encryption` defaults to `true`.
3. The two record-layer directions use different AEAD nonce prefixes, so the
   same key and counter are never reused in both directions.
4. `allow_ports` applies to explicit `remote_port` values too; an empty list
   forbids fixed ports. Defaults: `max_clients = 1024`,
   `max_ports_per_client = 64`, `authentication_timeout = 10`.
5. Relay authentication has a 10-second timeout and a connection cap; the relay
   only accepts public keys already registered through the overlay control plane.
6. The dashboard binds to `127.0.0.1` by default; enabling it requires
   `user` / `password` (at least 8 characters).
7. First-byte sniffing and TLS/WS handshakes run in per-connection tasks with
   5-second timeouts; a slow client cannot block the accept loop.

> Protocol **v2** is required. v1 clients are rejected with a protocol-version
> error and must be upgraded together with the server.

### 8.2 Operational hardening for public deployments

These are **deployment/operations** items, not application bugs. A public
production deployment should check each one:

1. **Rotate secrets**: use 32+ random bytes for `server.token` and
   `overlay.network_secret`. Never commit them; never put them in scripts.
2. **Do not run pure signaling/relay as root**: use a dedicated user and high
   ports. If you need the overlay TUN device, use systemd `User=trairi` plus
   `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` instead of full root.
3. **Firewall / security group**: expose only the required ports. Restrict
   `bind_port` and `relay_listen` by source IP where possible; expose overlay UDP
   ports only to the nodes that need them; never expose the dashboard publicly.
4. **Dashboard via SSH tunnel or TLS reverse proxy**: it uses HTTP Basic Auth;
   plain HTTP leaks the password to anyone on the path.
5. **Log level + rotation**: use `log.level: info` in production. Do not leave
   `debug` filling the disk; use logrotate or `log.file` daily rotation and
   monitor disk usage.
6. **Add TLS on the public Internet**: `protocol: tls` / `wss` with a valid
   certificate. `force_encryption` protects the Trairi record layer, not the
   transport metadata.
7. **Harden SSH too**: key-only auth, disable password login, fail2ban or source
   restrictions. SSH compromise is outside Trairi but still means host takeover.
8. **Keep dependencies fresh**: `cargo audit` currently reports no known
   vulnerabilities, only an unmaintained `rustls-pemfile` warning. Re-run it on
   every release and watch RustSec.
9. **Minimize the overlay ACL**: an empty ACL allows everything. If the network
   has less-trusted members, restrict node-to-node traffic with `overlay.acl`.
10. **Keep rollback artifacts**: before upgrading across protocol v2, back up
    the old binary/config and make sure every node can be upgraded.

See [SECURITY.md](SECURITY.md) for the vulnerability-reporting policy.

---

## 9. Known limitations

- **No QUIC**: KCP is available for reliable-UDP transport; QUIC is not
  implemented yet.
- **P2P is best-effort**: symmetric NAT, CGNAT, or UDP-blocking firewalls may
  force relay fallback. P2P uses KCP + smux; the owner and visitor must both
  run Trairi.
- **HTTP virtual hosts route per connection**: the backend is chosen from the
  first request's `Host`; later requests on the same keep-alive connection are
  not re-routed (this keeps WebSocket/keep-alive working).
- **`http_proxy` only supports CONNECT** (HTTPS tunnels); plain
  `GET http://...` proxying is not implemented.
- **Encryption/compression are connection-level**: set `client.use_encryption` /
  `client.use_compression`; there are no per-proxy switches.
- **No server hot reload**: restart the process after changing the server
  config; the client supports `/api/reload`.
- **Protocol v2 is not backward compatible**: v1 clients must be upgraded.
- **Dashboard authentication is mandatory when enabled**: if
  `dashboard.port > 0`, `user`/`password` are required, and the default bind is
  `127.0.0.1`.

---

## 10. Repository layout

```
src/
├─ main.rs / lib.rs     entry point (single binary; `mode` selects the role)
├─ cli.rs               CLI (run/server/client/validate/version)
├─ config.rs            config model and validation
├─ protocol.rs          control messages, stream headers, framing
├─ crypto.rs            HMAC auth + HKDF + ChaCha20-Poly1305
├─ stream.rs            compression/encryption record layer
├─ transport.rs         tcp/tls/ws/wss dialing and single-port sniffing
├─ util.rs              rate limiting, PROXY protocol, bidirectional copy, SNI/Host parsing
├─ server/
│  ├─ mod.rs            state, proxy registration, port allocation, groups
│  ├─ control.rs        handshake, login, control loop, work-connection dispatch
│  ├─ proxy.rs          tcp/udp/vhost-http/vhost-https forwarding
│  └─ dashboard.rs      dashboard and JSON API
├─ client/
│  ├─ mod.rs            connect, login, registration, control loop, admin API
│  └─ proxy.rs          local forwarding, visitors, health checks
└─ plugin/mod.rs        socks5 / http_proxy / static_file
tests/integration.rs    end-to-end tests
examples/               server/client YAML examples
scripts/                network-namespace and NAT test helpers
```

---

## 11. Overlay networking

Trairi includes a built-in overlay network: several machines form a virtual
LAN, each gets a `10.144.144.x` address, and they can `ping` each other without
router changes or public IPs.

### Architecture

```
   application / kernel network stack
         │  10.144.144.x IP packets
         ▼
   TUN device (Windows: wintun; Linux: /dev/net/tun)
         │
         ▼
   WireGuard (boringtun: handshake, encryption, replay protection, keepalive)
         │  UDP
         ▼
   peer  ── endpoint information distributed by the Trairi server
         ▲
         │  control plane (reuses the existing login/token/heartbeat channel)
   Trairi server: allocate virtual IPs, register public keys, distribute peer tables
```

- The data plane is standard WireGuard; the current release does **not** expose a
  standard WireGuard ingress, so all overlay nodes run Trairi.
- The control plane reuses the existing Trairi server; no second daemon.
- Routing is centralized allocation plus per-host `/32` routes; no OSPF, so
  behavior and troubleshooting stay simple.

### Usage

Server (public machine; clients must be able to reach its TCP port):

```yaml
mode: server
server:
  bind_port: 7000
  token: your-token
overlay:
  enable: true
  network_name: my-home-net
  network_secret: a-long-random-string
  ipv4_pool: 10.144.144.0/24
  udp_port: 11013
  stun_port: 0
  node_port: 0
```

Overlay port layout: `udp_port` is the main data plane; `stun_port` defaults to
`udp_port + 1`; `relay_listen` defaults to TCP `udp_port + 2`; and `node_port`
defaults to `udp_port + 3` when `node_ipv4` makes the server a node. All three
can be set explicitly. Set `relay_listen` to `0.0.0.0:0` to disable the TCP
relay.

Client (**must run as root / Administrator** to create the TUN device):

```yaml
mode: client
client:
  server_addr: 1.2.3.4
  server_port: 7000
  token: your-token
overlay:
  enable: true
  network_name: my-home-net
  network_secret: a-long-random-string
  ipv4: 10.144.144.2      # optional; the server can allocate it
  interface: trairi0
```

Once both sides are up:

```bash
ping 10.144.144.3        # ping the peer's virtual IP directly
```

### Implementation status

| Capability | Status |
|---|---|
| TUN device (Linux `/dev/net/tun`, Windows wintun) | ✅ |
| WireGuard data plane (handshake/encryption/keepalive/replay) | ✅ |
| Server coordination: IP allocation, public-key registration, peer tables | ✅ |
| Endpoint learning (server observes client public addresses) | ✅ |
| Automatic host routes and cleanup | ✅ |
| Full-mesh direct paths (when at least one side is reachable) | ✅ |
| **TCP relay fallback** (automatic when direct fails, reconnects with backoff) | ✅ |
| CLI: `trairi overlay status` / `trairi overlay cleanup` | ✅ |
| **Server itself as an overlay node** (`overlay.node_ipv4`) | ✅ |
| **STUN (NAT mapping detection)** | ✅ |
| **UDP hole punching (active probes + address learning)** | ✅ logic tested; real-NAT success still being tuned |
| **Subnet routing** (`proxy_networks`) | ✅ |
| **ACL** (`overlay.acl`, enforced at the sender) | ✅ |
| **MagicDNS** (node hostnames in the hosts file) | ✅ |

Path selection (dual-path send + ownership lock):

- Before ownership is decided, send on **both direct and relay**, so a one-way
  NAT path cannot silently swallow packets;
- receiving any **relay** packet locks the peer to relay (the relay is
  bidirectional and authenticated by public key);
- **direct** is locked only after a handshake response or cookie reply proves
  our outbound packets actually reached the peer;
- after a direct lock, if business data was sent and no reply arrives for
  15 seconds, fall back to dual-path and let relay take over;
- `overlay.direct: false` forces relay only.

### CLI

```bash
trairi overlay status -c client.yaml          # show overlay config summary
trairi overlay cleanup --interface trairi0    # clean up a stale TUN device
```

### P2 (STUN + hole punching) implementation and validation limits

- `src/overlay/stun.rs`: a minimal RFC 5389 implementation (Binding
  Request/Response + XOR-MAPPED-ADDRESS). The server answers on the overlay UDP
  port, so no external STUN server is required. A second port (`udp_port + 1`)
  is used to compare NAT mapping behavior.
- Hole punching: if the handshake is not established after 2 seconds, send a
  probe every 500 ms to the peer's server-observed public address. The receiver
  learns the real address and replies. Path usability is decided by the
  ownership lock above, not by a fixed timeout.
- Unit/integration tests verify that the timer sends probes and that receiving a
  probe corrects a stale peer address.
- A local netns + iptables lab (`scripts/overlay-nat-test.sh`) passes the relay
  path but cannot faithfully reproduce hole punching: Linux MASQUERADE changes
  the source port for different destinations (address-dependent mapping), which
  is not how most home routers behave. The lab is therefore not a reliable
  hole-punching reproduction.
- Public-Internet tests (public cloud VPS + home NAT) showed a stable
  endpoint-independent mapping and successful hole punching when both sides
  sent first; the implementation matches that strategy.

### Validation

- `cargo test`: 70 unit, 14 port-forwarding integration, 8 overlay integration
  tests.
- Overlay tests use an in-memory device + local UDP to exercise the WireGuard
  handshake and bidirectional IP forwarding.
- Regression test `relay_rescues_when_direct_path_is_dead`: both endpoints point
  into a black hole; only relay is usable; dual-path sending establishes the
  handshake and both sides lock to relay.
- Real-machine validation: two network namespaces with real TUN devices and
  routes; bidirectional `ping` passes (3/3, RTT 1–8 ms).
- Real cross-Internet validation: Debian `10.144.144.3` ↔ remote Windows
  `10.144.144.4` passes 5/5 with 0% loss (~31 ms); the server relays 116-byte
  data frames in both directions. A temporary WSL node `.5` ↔ `.3` / `.4` also
  passes with 0% loss.

### Caveats

- Requires **root / Administrator** to create the TUN device.
- On Windows, `wintun.dll` must be next to the executable or on the system path
  (or set `TRAIRI_WINTUN_DLL`).
- `/32` routes are removed on exit; after a hard kill, clean them with system
  tools. The virtual adapter itself is destroyed when the process exits.
- Do not overlap the virtual subnet with a real local subnet (default
  `10.144.144.0/24`; change `ipv4_pool` if needed).

### P3 (subnet routing / ACL / MagicDNS)

> These are optional enhancements. Trairi's core use case is still: multiple
> machines register with a public signaling server and can reach each other via
> virtual IPs; none of these features is required for that.

- **Subnet routing**: set `overlay.proxy_networks: [192.168.1.0/24]` on a node;
  the prefix is advertised to the overlay, and other nodes route that traffic to
  the advertising node. The advertising node must enable
  `net.ipv4.ip_forward=1`; if LAN devices need to reply, add SNAT, e.g.
  `iptables -t nat -A POSTROUTING -o <lan-iface> -s 10.144.144.0/24 -j MASQUERADE`.
  This is manual.
- **ACL**: the server distributes `overlay.acl`; each node matches rules in
  order on the **sender** side, first match wins, default allow.
  ⚠️ This is cooperative control, not a security boundary — a compromised node
  can ignore it.
- **MagicDNS**: writes node hostnames (`<hostname>` and `<hostname>.trairi`) into
  a managed block in the system hosts file
  (`# >>> trairi magic dns >>>` … `# <<< trairi magic dns <<<`), replacing the
  whole block whenever the peer table changes. It is not a DNS server and does
  not change the system resolver; writing hosts requires root/Administrator and
  only logs a warning on failure.

---

## 12. Changelog

- **0.3.6** (2026-11-13): vendor-fix smux idle-stream self-wake; fixes 100% CPU.
- **0.3.5** (2026-11-13): back off on server P2P/proxy UDP receive errors too.
- **0.3.4** (2026-11-13): back off on persistent overlay UDP/relay errors
  instead of spinning at 100% CPU.
- **0.3.3** (2026-11-12): rollback 0.3.2 direct-path preference after
  `HANDSHAKE(REKEY_TIMEOUT)` regression; restore 0.3.1 path behavior.
- **0.3.2** (2026-11-12): prefer direct overlay paths.
  - Direct has a 5-second grace window before relay locks.
  - A direct handshake response can reclaim a relay-locked peer.
  - New/changed peer endpoints re-open direct path selection.
- **0.3.1** (2026-11-12): fix overlay port defaults.
  - `server.kcp` is opt-in (`false` by default) so it cannot silently occupy
    UDP `bind_port` when `overlay.udp_port` uses the same port.
  - `overlay.relay_listen` is empty by default and derives from
    `overlay.udp_port + 2`; explicit values still win.
  - `overlay.stun_port` / `overlay.node_port` can override the derived
    `+1` / `+3` ports.
- **0.3.0** (2026-11-12): KCP + P2P + Android bridge.
  - KCP reliable-UDP transport (`protocol: kcp`).
  - P2P proxy with LAN endpoint preference, public UDP punch, KCP + smux, and
    automatic relay fallback.
  - Relay auto-reconnect, weighted group balancing, global defaults, log
    retention, and dashboard user display.
  - Rust Android VpnService TUN bridge for the Flutter client.
- **0.2.0** (2026-11-10): security hardening.
  - Protocol v2: full-field Hello HMAC + server replay cache; per-direction AEAD
    nonce prefixes.
  - Per-connection accept/sniffing with 5-second TLS/WS/first-byte timeouts.
  - Relay auth timeout + connection cap + overlay public-key allowlist + no
    active-key replacement.
  - `allow_ports` enforced for explicit ports; defaults changed to
    `authentication_timeout=10`, `max_clients=1024`, `max_ports_per_client=64`.
  - Dashboard defaults to `127.0.0.1`, requires authentication, escapes
    client-controlled fields, and adds a CSP.
  - Decompression cap of 4 MiB; server token required; `force_encryption=true`.
  - ⚠️ v1 clients are not compatible; upgrade all nodes together.

See [CHANGELOG.md](CHANGELOG.md) for details.

---

## 13. License

MIT. See [LICENSE](LICENSE).

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). For security
reports, use [SECURITY.md](SECURITY.md), not a public issue.
