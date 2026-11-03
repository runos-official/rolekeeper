# Changelog

All notable changes to rolekeeper are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline checks that `VERSION` has a section here (`## vX.Y.Z`).

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
