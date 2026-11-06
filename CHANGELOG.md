# Changelog

All notable changes to rolekeeper are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline checks that `VERSION` has a section here (`## vX.Y.Z`).

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
