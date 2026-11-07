# Changelog

All notable changes to rolekeeper are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline checks that `VERSION` has a section here (`## vX.Y.Z`).

## Unreleased

### Security
- **The pod patches only its own admission objects.** Before, the ClusterRole
  `roid-k8s-applier` in `deploy/relay.yaml` let the pod patch every
  ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding on the
  cluster. A pod that was taken over could then switch off any admission
  policy, including a guard that an installer puts in front of the pod's own
  writes. The patch now names the deny policy and its binding
  (`runos-deny-writes`). Get and list stay cluster-wide, because Kubernetes
  cannot limit list to a name. The in-place repair of the deny policy works
  as before. Re-apply `deploy/relay.yaml` to take the narrower role. A test
  in `deploy` pins the rule.

## v0.2.0

This repository is now the source of rolekeeper. Before this release it was a
published copy of code that lived in a private repository; from here on the code,
the tests and the release tools are edited, reviewed and released here, and pull
requests are welcome. The applier does not behave differently: the same bundles
are accepted and refused, and the same objects are applied. The pod's
configuration, its manifests and its image are as before. The version changes
because the Go packages moved.

### Changed
- **The packages are importable.** The `internal/` directory is gone. Other
  modules can import `github.com/runos-official/rolekeeper/` followed by one of:
  `applier`, `bundle`, `compile`, `conformance`, `deploy`, `kobj`, `kubeapi`,
  `reconcile`, `signer`, `signer/jws`, `signer/keys`, `signer/revlog`,
  `signer/roottrust` and `signer/token`. The API is v0: it may change between
  minor versions. RunOS imports these packages instead of keeping its own copy.
- **Test names and test file names changed.** They no longer carry review or
  tracking ids; they say what they test. A test that you ran by name has a new
  name. No test was removed.
- **`compile` no longer says that its projection lives elsewhere.** The package
  comment now says what the package holds.

### Added
- **Unit tests for the packages that lost tests in the move.** `compile` (lint,
  the deny list, `Held`, `ClaimGroups`), `reconcile` (the reconciler against an
  in-memory cluster, the deny-list safety rules and the kubectl client), `kobj`
  and `signer` have hand-built tests. Measured coverage with the race detector
  is `compile` 97.7%, `reconcile` 96.0%, `kobj` 99.2% and `signer` 97.4%.
- **Coverage floors.** `scripts/coverage-floors.txt` holds the lowest coverage of
  each package, `scripts/coverage-floors` checks it, and CI and the release
  checks run it. `make coverage` runs it locally.
- **Conformance vectors.** `testdata/conformance/vectors.json` is a frozen set
  of signed bundles, fresh tokens, refusals and a key set, each with the outcome
  a verifier must reach, made with TEST-ONLY keys. The package `conformance`
  runs it. `docs/conformance.md` says how the signing side regenerates and runs
  it.
- **Public-safety gates for a repository that people push to.** The leak checks
  now also read commit messages and file names (`scripts/msgcheck.py`), with
  `commit-msg` and `pre-push` hooks. `scripts/denycheck.py --hash WORD` adds a
  name to the rules without writing it into the repository.
- **CI runs on `dev` and `main`.** It runs on every push and pull request to
  either branch: formatting, `go mod tidy` and `go mod verify`, `go vet`, a
  build without cgo, the tests with the race detector, the coverage floors,
  `staticcheck`, `govulncheck`, the leak gates and an image build. The leak gates
  also run for every other branch.

### Removed
- **The record of a generating export.** `SOURCE`, `scripts/treehash.py`, the
  `make sourcecheck` target and the CI and release steps that checked them.

## v0.1.1

No change to what the binary does. This release adds the way it is released:
a candidate (`vX.Y.Z-rc.N`) and its final are cut from the same commit by a
release pipeline that runs the checks first, and the image digest, platforms
and attestation are read back and verified.

### Added
- **Release candidates.** The release workflow accepts `vX.Y.Z-rc.N` tags and
  builds the same multi-architecture, attested image for them.
- **Release checks.** `scripts/release-check.sh` runs every gate without a side
  effect before a tag is cut. `scripts/image-digest.sh` reads the digest and
  platforms of a published image back from the registry.

## v0.1.0

First public release. rolekeeper is the in-cluster component that keeps
Kubernetes RBAC roles and the deny list in line with the access decisions that
RunOS's identity service signs. It was the roid Kubernetes applier before, in a
private image that clusters could not pull. This release publishes the same
code, the verifying and applying side only, in a public image.

### Added
- **`--version` and `--help`.** The binary prints its version or its main
  settings and exits. It takes no other argument, as before.

### Changed
- **The image is `ghcr.io/runos-official/rolekeeper`.** It is public. It uses the
  same distroless base and the same non-root user (65532) as the image it
  replaces. A pod that ran the old image changes only its image reference.
- **The binary is `/rolekeeper`.** It is the image entry point. The environment
  variables (`ROID_K8S_*`) and their meaning are unchanged.
- **The relay transport only.** The pull transport's enrolment with a service
  account token is not part of this build.

### Security
- Releases carry a keyless build-provenance attestation and a software bill of
  materials.
