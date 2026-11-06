# Relay test vectors

Public test data for the relay transport. Conductor copies this directory; a
drift test compares the copies.

- `trust.json`: the pinned trust (public keys only, example ids).
- `meta.json`: the verification time, account, cluster, nonce and digests.
- `envelope.json`: the envelope as roid serves it. `token.txt` and `body.json`
  are its two halves. `body.sha256` is the token id.
- `body.gz`: gzip level 6 of `body.json`, made by Go. Conductor's own gzip of
  `body.json` must give the same envelope after `RebuildEnvelope`.
- `fresh.jwt`: the fresh token for `meta.nonce` and `meta.content_digest`.
- `refusal-cluster.jwt`, `refusal-retired.jwt`: roid's signed refusals.

All tokens verify at `meta.now`. Regenerate: `ROID_UPDATE_VECTORS=1 go test
./applier -run TestRelayVectors` from `k8s/`.
