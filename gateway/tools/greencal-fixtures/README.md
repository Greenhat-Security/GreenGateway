# GreenCal canonicalization fixtures

Regenerates `gateway/src/connections/greencal_actor_fixtures.json`, the cases that pin this
gateway's canonical JSON and request digest to GreenCal's.

GreenCal's `docs/scoped-gateway-v2.md` asks for this specifically: *"Gateway must add matching
cross-language fixtures before activation, rather than guessing how to hash JSON."* The digest is
taken over a canonical form of the request rather than the bytes on the wire, so the two
implementations have to agree exactly or every request is rejected with `actor_required` — a failure
that looks identical to tampering.

Nothing here is hand-written. `extract.mjs` pulls `canonicalJson` and `requestDigest` out of
GreenCal's `src/gateway/scopedGatewayActor.ts` by source text, strips only the TypeScript
annotations, and refuses to continue if any annotation survives the transform. `fixtures.mjs` then
runs those functions under Node and prints what they produce.

## Regenerating

```sh
gh api repos/Greenhat-Security/GreenCal/contents/src/gateway/scopedGatewayActor.ts \
  --jq '.content' | base64 -d > scopedGatewayActor.ts
node extract.mjs > /dev/null          # writes canonical.mjs; prints the transformed source
node fixtures.mjs > ../../src/connections/greencal_actor_fixtures.json
```

Read the transformed source that `extract.mjs` prints before trusting the output. Do not edit the
JSON by hand: a fixture edited to match a failing Rust implementation defeats the entire point of
having it.

## What the cases are for

They are chosen where Rust and JavaScript can plausibly disagree, not where agreement is obvious.
The important ones are the key-ordering cases. JavaScript's default sort compares UTF-16 code units,
so `U+10000` sorts *below* `U+FFFF` because its lead surrogate is `0xD800`; Rust's `str` ordering
compares UTF-8 bytes and puts them the other way round. An implementation that sorts natively agrees
with these fixtures on every ASCII payload and diverges the first time a meeting title contains an
emoji.

The remainder cover control-character escaping, non-ASCII passing through literally, negative zero,
the safe-integer boundaries, array order, empty keys, nesting near the shared depth cap, and a
mutation body carrying its `requestKey`.
