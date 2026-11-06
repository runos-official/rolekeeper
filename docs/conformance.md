# Conformance vectors

rolekeeper verifies what RunOS's identity service (roid) signs. The two sides
live in different repositories, so a change on one side could break the other
without a test noticing. The conformance vectors close that gap: one frozen
file of signed artifacts and the outcome that a verifier must reach for each.

The file is `testdata/conformance/vectors.json`. The package
[`conformance`](../conformance) loads it and runs it. `vectors.sha256` holds the
checksum of the file.

## What the file holds

- The **trust** that a verifier pins: the issuer name, the cluster, the public
  key of the offline root, and the key set that the root published.
- A fixed **clock** (`2030-01-02T03:04:05Z`), the **account** (`acct-a`) and
  the **cluster** (`cl-1`).
- **Cases.** Each case has an id, a kind, a description, the input, and the
  expected outcome.

| Kind | Input | The verifier call |
|---|---|---|
| `bundle` | an envelope: the token and the body | `Verifier.Verify` |
| `fresh` | a token, the applier's nonce, the content digest | `Verifier.VerifyFresh` |
| `refusal` | a token | `Verifier.VerifyRefusal` |
| `keyset` | a root-signed key set | `Verifier.UpdateKeys` |

A case may set its own `now`, `cluster` or `account`, to model a verifier with
another clock, another cluster or another expected account.

The expected outcome is either `ok` with the facts (the bundle version and
content digest, or the reason of a refusal), or an `error` code. The codes are
the same on every implementation:

| Code | Meaning |
|---|---|
| `bad_format` | the envelope or the body is not a bundle of format 1 |
| `not_an_rbac_bundle` | the token is signed, but is not an RBAC bundle token |
| `digest_mismatch` | the body is not the one the token names |
| `wrong_cluster` | the body names another cluster than the verifier's |
| `wrong_account` | the account is not the one the verifier expects |
| `fresh_token_mismatch` | the fresh token is not for this nonce and this content |
| `bad_refusal` | the token is not a refusal, or names an unknown reason |
| `bad_signature` | the signature does not verify under the key of the header |
| `unknown_key` | the key id is not in the pinned key set |
| `algorithm_not_allowed` | the algorithm is not EdDSA or ES256 |
| `expired`, `not_yet_valid` | the token is outside its life, with 30 seconds of leeway |
| `wrong_audience` | the token is for another cluster |
| `malformed` | the text is not a compact signed object |

The file has accepted cases of every kind, and refused cases for each way that
a signature, a digest, a clock, a cluster, an account, an algorithm header or a
key can be wrong.

## The keys are for tests only

Every private key behind the vectors is a TEST-ONLY key. Its seed is the
SHA-256 of the text `rolekeeper-conformance-v1/TEST-ONLY/` followed by a label,
and the key is the Ed25519 key of that seed. Anybody can compute it. The file
holds public keys and signed tokens only, and no real system trusts these keys.

| Label | Role | Key id in custody |
|---|---|---|
| `root` | the offline root that the trust pins | `conformance-test-only-root` |
| `other-root` | a root that nobody pinned | `conformance-test-only-other-root` |
| `bundle-1` | the active policy-bundle key | `conformance-test-only-bundle-1` |
| `bundle-2` | the standby policy-bundle key | `conformance-test-only-bundle-2` |
| `stranger`, `stranger-two` | a signer that is not in the key set | `conformance-test-only-stranger` |
| `forged`, `forged-two` | keys that sign under the ids of `bundle-1` and `bundle-2` | the ids of `bundle-1` and `bundle-2` |

Ed25519 signatures are deterministic. With the same keys, the same clock and
the same claims, a signer writes the same bytes every time. A token
that gets a random id when it is really issued (a refusal) has a fixed id in
the vectors (`refusal-conformance-0001` and so on).

## On the rolekeeper side

```sh
go test ./conformance
```

runs every case against the verifier of this checkout, then tampers with each
accepted case in every place that a signature or a digest covers (each
character of a signature, of a header and of the claims, each byte of a body)
and requires a refusal. It also checks that the file matches `vectors.sha256`,
and that the generator writes exactly the bytes of the file.

The file is **frozen**. A released file never changes. If a change makes
`TestEveryVectorGetsTheOutcomeTheFileExpects` fail, the change alters what a
verifier decides about an artifact that is already out in the field. Do not edit
the file to make the test pass. Either fix the change, or add a new vector file
(`vectors-v2.json`, with its own checksum and test) and say in `CHANGELOG.md`
which verdict changed and why. Older verifiers keep running the old file.

If the generator test fails while the vector test passes, the signing code
writes other bytes than before (for example a new field in the body). Old
verifiers may refuse them. Add a new vector version for the new bytes.

To rewrite the file for a new version, after a review of the change:

```sh
go test ./conformance -run TestFileIsWhatTheGeneratorWrites -update
```

The generator stops when a verifier of today does not reach the outcome that the
generator wrote by hand for a case, so it never records a guess.

## On the roid side

roid signs with its own code and its own key custody, so it runs the vectors in
two ways. Both belong in the fast
test lane: they take seconds.

**Run the file.** Load the file from the pinned module and check every case:

```go
dir := /* go list -m -f '{{.Dir}}' github.com/runos-official/rolekeeper */
f, err := conformance.Load(filepath.Join(dir, "testdata", "conformance", "vectors.json"))
if err != nil { t.Fatal(err) }
for _, c := range f.Cases {
	if err := f.Check(c, t.TempDir()); err != nil { t.Error(err) }
}
```

This proves that the rolekeeper version roid pins still reaches every verdict in
the file.

**Regenerate the file.** Rebuild the signing side with roid's real code:

1. Derive the keys of the table above from their labels, and use them as the
   keys of a test custody backend. The key ids are the ones in the table.
2. Bootstrap the policy-bundle key set with `bundle-1` as the active key and
   `bundle-2` as the standby. Pin `root` as the offline root and publish the
   set with it.
3. Set the clock to the clock of the file, the issuer to the issuer of the
   trust in the file, and the account and the cluster to those of the file.
4. Seal the same bundle bodies that the `bundle-ok`, `bundle-deny-only-ok` and
   `bundle-retire-ok` cases hold (decode a body from the file and seal it), and
   the fresh token for `fresh-ok`.
5. Compare roid's tokens and bodies with the file, byte for byte.

A difference means that roid writes something other than the file describes: a
claim, a lifetime, the encoding of the body, the header. Before that change
ships, publish a vector version that holds the new bytes, so that every
verifier that runs in a cluster is tested against them. A new field that old
verifiers cannot digest is the case this check exists for.

## Order of changes

- A change that only the verifier makes (a stricter check): change rolekeeper,
  add refused cases, release. roid picks up the release.
- A change that only the signer makes (a new claim): add the vectors in
  rolekeeper first, release, then change roid.
- A security fix that touches both sides: the fix and its vectors go into
  rolekeeper first, then roid pins the release that holds them.
