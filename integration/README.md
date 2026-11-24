# Isolated cross-repository acceptance

[`stage_demo.py`](stage_demo.py) exercises the Attestor endpoint with the sibling
`confidential-ai-example` client, its pinned policies, a temporary HTTPS Nginx
frontend, and a synthetic downstream responder. It is an opt-in integration
check, not part of the Attestor runtime or the example client package. The
script connects to an operator-started Attestor on loopback; it does not start
or stop that collector or change public listeners.

On a compatible SNP/vTPM host, start Attestor as described in the
[deployment guide](../deploy/README.md), then run from the Attestor checkout:

```sh
../confidential-ai-example/.venv/bin/python integration/stage_demo.py \
  --out /private/new-stage-run \
  --certificate-dir /private/attestor-stage-certs \
  --match-verifier-policy ../confidential-ai-example/profiles/verifier-genoa-stage-registry.json \
  --mismatch-verifier-policy ../confidential-ai-example/profiles/verifier-genoa-stage-mismatch.json
```

The example and Confido checkouts must be siblings of this checkout. Replace
`/private` with a private local directory. The output path must not exist.
The script uses real hardware evidence and a synthetic downstream response; it
does not evaluate an external inference service. Keep run archives private.
