# Changelog

## 0.3.5 — 2026-11-13

- Added the same 200 ms error backoff to the remaining UDP receive loops:
  server P2P rendezvous and server UDP proxy.
- These loops could still spin when a long-lived UDP socket returned errors
  repeatedly.

## 0.3.4 — 2026-11-13

- Fixed CPU spin when overlay/UDP/relay `recv` or `accept` returns a persistent
  error (for example ICMP port unreachable). The loops now back off 200 ms
  instead of immediately retrying.
- This targets long-running 100% CPU in server/client processes, especially
  after a failed direct path leaves an unreachable UDP endpoint.

## 0.3.3 — 2026-11-12

- Reverted the 0.3.2 direct-path grace/relay preference change. It caused a
  regression where a slow or one-way direct path was forced to relay after
  5 seconds, and relay cannot reach a server-node peer (server node has no
  relay registration). Result: `HANDSHAKE(REKEY_TIMEOUT)` and complete overlay
  outage for server-node `.1`.
- Restored the 0.3.1 path-selection behavior until direct-path arbitration can
  be redesigned and tested with real NAT.

## 0.3.2 — 2026-11-12

- Overlay path selection now prefers direct when a peer has a usable UDP
  endpoint. Relay packets no longer preempt a direct handshake immediately.
- Added a 5-second relay grace window; if no direct handshake response arrives,
  relay takes over. A direct handshake response can reclaim the peer from relay.
- When the coordinator later learns or changes a peer endpoint, the peer is
  re-evaluated for direct instead of staying relay-locked forever.
- This targets Android/cellular or Wi-Fi clients that were falling back to the
  signaling server even when UDP hole punching could work.

## 0.3.1 — 2026-11-12

- `server.kcp` now defaults to **false**, so KCP does not silently occupy UDP
  `bind_port` and collide with `overlay.udp_port`.
- `overlay.relay_listen` now defaults to empty and is derived from
  `overlay.udp_port + 2`; explicit values still win. This removes the hard-coded
  `0.0.0.0:11012` default that failed on servers using a custom overlay port.
- Added validation for the KCP/overlay UDP port collision.
- Added `overlay.stun_port` and `overlay.node_port` (0 = auto), so the derived
  `udp_port + 1/+3` ports can be overridden explicitly.
- Overlay port layout is documented as `udp_port`, `+1` STUN, `+2` relay,
  `+3` server node.

## 0.3.0 — 2026-11-12

- Added P2P proxy (`type: p2p`): server rendezvous exchanges UDP endpoints,
  owner/visitor punch through and use KCP + smux for a direct encrypted path,
  with automatic server-relay fallback. Same-LAN peers try their private
  endpoints first.
- Added KCP (reliable UDP) transport: `protocol: kcp`; the server listens for
  KCP on UDP `bind_port` when `server.kcp` is enabled (default true). The
  existing token/HMAC and ChaCha20-Poly1305 record layer are reused.
- Added the Rust Android `VpnService` TUN bridge used by the Flutter client.
- STUN binding now retries within its timeout, tolerating occasional UDP loss.
- Relay connections now reconnect automatically with exponential backoff
  (1s → 30s); the old connection cannot clear a newer one.
- Client/global defaults are applied consistently:
  `client.heartbeat_interval`, `client.bandwidth_limit`, and
  `client/server.proxy_protocol_version` now take effect; per-proxy values win.
- `proxies[].weight` is implemented for group load balancing (weighted round-robin).
- `log.max_days` now limits retained daily log files.
- `client.user` is shown in the dashboard.
- Removed the ineffective per-proxy `use_encryption` / `use_compression` fields;
  encryption and compression remain connection-level.

## 0.2.0 — 2026-11-10

Security hardening release.

- Protocol v2: the Hello HMAC covers every handshake field; the server keeps a
  `(salt, timestamp)` replay cache; `force_encryption` defaults to `true`.
- The AEAD record layer uses a separate nonce direction prefix for each
  direction, removing cross-direction nonce reuse.
- The accept loop no longer blocks on client data: TLS/WebSocket/first-byte
  sniffing runs in a per-connection task with 5-second timeouts.
- Relay authentication has a 10-second timeout, a connection cap, an overlay
  public-key allowlist, and rejects replacement of an active public key.
- `allow_ports` now applies to explicit `remote_port` values; an empty
  allowlist denies fixed ports.
- Defaults: `authentication_timeout=10`, `max_clients=1024`,
  `max_ports_per_client=64`; a server token is required.
- Dashboard defaults to `127.0.0.1`; enabling it requires a password; the web UI
  escapes client-controlled fields and adds a CSP.
- Decompression is capped at 4 MiB.
- **Breaking:** protocol v2 is not compatible with v1 clients.

## 0.1.0

Initial single-binary server/client, TCP/UDP/HTTP vhost forwarding, STUN,
WireGuard overlay, TCP relay fallback, and Windows/Linux builds.
