# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ |
| < 0.2 | ❌ (protocol v1, no longer compatible) |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting:

<https://github.com/AKHYui/Trairi/security/advisories/new>

Include:

- affected version / commit;
- a minimal reproduction;
- expected vs actual behavior;
- impact (confidentiality / integrity / availability);
- whether the issue requires a valid token, an overlay member, or only network access.

We will acknowledge the report and coordinate a fix and disclosure timeline.

## Deployment security

Trairi is a self-hosted tunneling / overlay tool. The server is a high-value
component: anyone who can authenticate to it can create proxy listeners and
join the configured overlay network.

For public deployments:

- use a long random `server.token` and `overlay.network_secret`;
- keep `force_encryption = true`;
- keep `dashboard` bound to `127.0.0.1` (or disable it) and always set a password;
- set `allow_ports`, `max_clients`, `max_ports_per_client`, and a short
  `authentication_timeout`;
- do **not** run the signaling/relay process as root unless you need the
  overlay TUN device, and prefer systemd capabilities over full root;
- restrict the control/relay/overlay ports with a firewall or cloud security group;
- add TLS (`protocol: tls` / `wss`) for the control channel;
- keep logs rotated and monitored.

See the “Security” section in [README.md](README.md) for the full operational checklist.

## Scope

In scope:

- remote code execution, privilege escalation, or host takeover;
- authentication / authorization bypass, replay, or session forgery;
- cross-tenant data exposure or proxy/port isolation bypass;
- denial of service that is trivial and unauthenticated;
- cryptographic weaknesses in the control or record layer.

Out of scope:

- attacks that require the server token or an already-compromised overlay member,
  unless they demonstrate privilege escalation beyond that role;
- misconfiguration of the host, firewall, TLS certificates, or SSH;
- vulnerabilities in third-party dependencies (please report upstream, but we
  will update when a fixed release is available).
