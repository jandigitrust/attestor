# Building Attestor 0.2

Run from the repository root with Rust 1.98.0 and the native TPM2-TSS
development packages installed. On Ubuntu, the prerequisites are
`build-essential pkg-config perl clang libclang-dev libtss2-dev`.
Cargo uses the committed lockfile and pinned Teraveri Evidence revision;
no sibling source checkout is needed.

```sh
cargo fmt --manifest-path server/Cargo.toml -- --check
cargo test --locked --manifest-path server/Cargo.toml
cargo build --locked --manifest-path server/Cargo.toml
python3 -m unittest discover -s server/tests -v
python3 -m unittest discover -s tests -v
```

The tests do not require TPM hardware. A live deployment must additionally
exercise fresh challenge collection on a compatible host, an accepted and
rejected reference in Confido, and the intended HTTPS peer check. Record the
exact Attestor, Evidence, Confido, policy, and reference identities for that run.

The RPM release workflow packages the `attestor-server` binary, project licence,
notices, and a dependency attribution archive built from locked Cargo metadata.
Review the resulting package and third-party terms before a release.
