# Changelog

## Unreleased

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
