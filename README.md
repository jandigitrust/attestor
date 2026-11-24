# Attestor 0.2

Attestor collects challenge-bound evidence from an Azure AMD SEV-SNP confidential VM.
It exposes the existing `POST /tee-report` wire contract for the Confido verifier
and its other callers. The collector returns an SNP report, a signed vTPM quote,
IMA measurements, and the configured certificate. It uses the pinned
[Teraveri Evidence](https://github.com/teraveri/evidence) protocol and core crates
to construct the response and reject inconsistent local snapshots.

Collection is not appraisal: Attestor does not decide whether the platform,
reference values, application, or TLS peer is trustworthy. Confido supplies the
verifier; a relying application separately authenticates its peer and decides
whether to send traffic. The current evidence profile covers measured boot and
kernel modules, not application code, models, GPU state, or external inference.

## Components

| Path | Purpose |
| --- | --- |
| [`server/`](server/README.md) | Native SNP/vTPM/IMA collection, certificate configuration, and report endpoint. |
| [`deploy/`](deploy/README.md) | Collector service templates for deployment operators. |
| [`integration/`](integration/README.md) | Optional isolated acceptance with the sibling client and synthetic downstream responder. |
| [`scripts/`](scripts/README.md) | Packaging and dependency attribution support. |
| [`third_party/`](third_party/README.md) | Preserved upstream licences and provenance for binary releases. |

## Build and test

Rust 1.98.0 is pinned in `rust-toolchain.toml`. The locked server graph pins
Evidence 0.2.0 at commit `900d420b0928c4693e1143aa33a33ab670147e3c`.
Install the native TPM2-TSS development libraries before building; see
[BUILDING.md](BUILDING.md) for commands and package prerequisites.

## Endpoint and deployment

`POST /tee-report` accepts an `AttestationRequest` with a caller-supplied nonce
and returns an `AttestationResponse`. The response includes the certificate used
for the quote binding. `HEAD /tee-report` returns 204 without credentials so a
caller can separately probe its observed HTTPS peer. The collector itself serves
HTTP; deploy it behind the intended HTTPS frontend and use the same certificate
and key there. A quote-bound certificate alone does not bind evidence to the
caller's observed TLS session.

The launcher defaults to `/etc/confido` when that certificate directory exists
for the current demo deployment, and otherwise uses `/tmp/confido` for local
development. The directory can be overridden. Do not expose the HTTP collector
outside the intended deployment boundary. The launcher validates certificate
configuration before replacing a listener and only stops a recognized collector
process. See [`server/README.md`](server/README.md) for details. The current
GENXT demo service template is in [`deploy/genxt-demo/`](deploy/genxt-demo/).

## Origin and licence

Attestor shares its pre-extraction Git history with
[JAN Confido](https://github.com/jandigitrust/confido). Confido began as
[GENXT's attested TLS prototype](https://github.com/elixir-cloud-aai/generic-issues/issues/17).
The Attestor source starts from the signed Confido checkpoint
[`89f2c28`](https://github.com/jandigitrust/confido/commit/89f2c288ca3cddeb5840f3b107b06d5568f2a81d).
Project-authored material is [Apache-2.0](LICENSE); third-party material retains
its original terms, recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
