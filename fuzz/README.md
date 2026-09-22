# Pure security corpus

This directory contains #435's small deterministic synthetic seed corpus.
The test-only worker in `gateway/tests/support/security_corpus.rs` and controller in
`scripts/security_corpus.py` reuse actual parser entry points and existing
locked dependencies, without a second parser or separate fuzz toolchain.

From the repository root, using the exact `build-tools.json` pins:

```sh
python scripts/security_corpus.py --mode regression
```

See the [run, resource, replay and private-triage contract](../docs/testing/security-corpus.md).
Do not commit generated JWTs, keys, production identities, raw sensitive
findings or automatic crash dumps.
