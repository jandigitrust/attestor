# Repository build checks

These Python tests exercise build and packaging helpers without TPM hardware:

- `test_attribution.py` checks Git revision consistency, inherited workspace
  notices, and exclusion of the Attestor crate from dependency attribution.

Run `python3 -m unittest discover -s tests -v` from the repository root.
Collector launcher tests live in `server/tests`. Live hardware and HTTPS-peer
acceptance are separate from these offline checks.
