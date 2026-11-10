# Contributing

Thanks for taking a look at Trairi.

## Development

```bash
cargo test
cargo clippy --all-targets
```

- Rust edition 2024; keep `cargo fmt` clean for files you touch.
- The overlay/TUN integration tests are skipped unless `TRAIRI_TUN_TEST=1`
  and the test runs as root on Linux.
- Please do not commit real server addresses, tokens, passwords, or generated
  `dist/` artifacts. See `.gitignore` for the expected layout.

## Pull requests

- Keep changes focused and describe the user-visible behavior.
- Add or update tests for protocol, authentication, or forwarding changes.
- For security-sensitive changes, explain the threat model in the PR description.
- Protocol changes must bump `PROTOCOL_VERSION` and update both client and server.

## Security

Please do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
