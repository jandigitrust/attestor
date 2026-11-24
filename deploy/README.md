# Deployment templates

Attestor runs as an independent collector service. The
[`genxt-demo/`](genxt-demo/) unit is configured for the current GENXT demo's
loopback listener, certificate directory, and TLS hostname. Review these values
and the matching HTTPS frontend before installing it on a host. The consuming
application only calls the public `/tee-report` endpoint; it does not manage
this unit.

For an isolated hardware acceptance run, build and start a separate collector
with a certificate for `localhost` on a private loopback port. From the Attestor
repository root on a compatible host:

```sh
cargo build --locked --manifest-path server/Cargo.toml
sudo server/target/debug/attestor-server 127.0.0.1:18001 \
  /private/attestor-stage-certs sha256 --tls-hostname localhost
```

Replace `/private` with a private local directory. The process remains under
the operator's control while the example's stage runner uses that endpoint and
certificate directory. Stop it separately after the run; the example does not
start or stop this collector.
