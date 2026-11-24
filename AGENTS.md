# Agent guidance

Attestor 0.2 owns native SNP/vTPM/IMA collection and `POST /tee-report`.
Start with `README.md`, `server/README.md`, and `BUILDING.md`.
`server/` contains the Rust collector and launcher; `scripts/` supports
packaging; `integration/` is an optional cross-repository acceptance harness.
The pinned Teraveri Evidence crates define wire structures and
bounded snapshot checks. Confido owns evidence appraisal and policy.

## Context and private data

- Scope searches to source, tests, and relevant documentation. Exclude
  `target/`, build outputs, caches, and logs from broad searches.
- Do not print, attach, or paste caches, binaries, private keys, credentials,
  or raw live evidence into model context, issues, or PRs. Report only
  necessary metadata, counts, hashes, or redacted fields.
- `.gitignore` limits accidental staging; it does not control what an agent
  reads or sends to a model. Check tool output before exposing it.

## Verification

Use the focused commands in `BUILDING.md`. Before handing off, check
`git status --short` and `git diff --check`.
