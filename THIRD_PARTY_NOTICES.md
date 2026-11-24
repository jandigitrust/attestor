# Third-party material

The root [LICENSE](LICENSE) applies to Attestor's project-authored material.
It does not replace dependency licences, copyright notices, or attribution
requirements.

## Preserved source material

- `azure-cvm-tooling` / `az-snp-vtpm`, pinned at
  `9c6bff6c959994da280f8b3b5bad62a1600063d0`: Microsoft/Kinvolk, MIT.
  `server/src/collector.rs` retains the source copyright and licence notice.
  Attestor's changes add multi-bank collection and expose quote data.
  The upstream terms are in
  [`third_party/azure-cvm-tooling-LICENSE`](third_party/azure-cvm-tooling-LICENSE).
- The pinned [Teraveri Evidence](https://github.com/teraveri/evidence)
  crates have their own project and third-party attribution. Their files are
  included in the resolved binary dependency inventory.
- Cargo dependencies retain their authors' terms. The supplemental files
  in [`third_party/`](third_party/README.md) preserve licences omitted by
  selected published crates, with provenance and hashes.

## Binary releases

The native collector enables vendored OpenSSL, which can be compiled into
distributed binaries. Its licence files and the terms of the Rust wrapper
must accompany a release. Other resolved dependencies may carry MIT, BSD,
ISC, Apache, or other terms; this list is not exhaustive.

The RPM workflow builds a third-party licence archive from the locked
Linux-target Cargo metadata. It preserves resolved dependency notices and
records package identities. The archive is intentionally conservative:
listing a dependency does not claim it is linked into the final binary.
The RPM installs the root licence, this document, and the generated archive
under `/usr/share/licenses/attestor-server/`.

Before publishing a binary, review the resolved inventory, any file-specific
terms, the external Azure tooling provenance, and the actual release artifact.
