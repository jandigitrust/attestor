# Attestor collector

The native binary reads AMD SEV-SNP, vTPM, and IMA evidence on a compatible
host. `POST /tee-report` accepts a challenge and returns a bounded snapshot.
`HEAD /tee-report` returns 204 for a separate HTTPS-peer probe. Before
returning evidence, the collector invokes the pinned `evidence-core` snapshot
check. This consistency check is not policy appraisal; Confido owns appraisal.

| Path | Role |
| --- | --- |
| [`src/main.rs`](src/main.rs) | HTTP routes, challenge-bound collection, certificate handling, and startup. |
| [`src/collector.rs`](src/collector.rs) | Host SNP/vTPM collection and multi-bank TPM quote path. |
| [`src/tests.rs`](src/tests.rs), [`tests/test_launcher.py`](tests/test_launcher.py) | Collector and safe-launcher tests. |
| [`run.sh`](run.sh), [`stop_existing.py`](stop_existing.py) | Development launcher and controlled replacement of a conflicting collector. |
| [`Cargo.toml`](Cargo.toml), `Cargo.lock`, [`specs/attestor-server.spec`](specs/attestor-server.spec) | Locked build and RPM packaging. |

Run the build and tests in [BUILDING.md](../BUILDING.md). `run.sh` validates
certificate configuration before stopping a recognized listener. It accepts
the old `confido-server` process name only to support migration of the current
demo deployment; an unrelated listener is never stopped. Configure the
intended bind address, certificate directory, and HTTPS frontend before use.
