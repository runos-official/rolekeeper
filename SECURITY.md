# Security Policy

## Reporting a vulnerability

If you find a vulnerability in rolekeeper or in any other RunOS product or
service, report it responsibly.

**E-mail:** security@runos.com

Please include:

- a description of the vulnerability,
- the steps to reproduce it,
- the impact that you expect.

We acknowledge reports within 8 hours and aim to give a fix or a mitigation
plan within 3 days for critical issues. Please do not open a public issue for a
vulnerability.

## What rolekeeper trusts, and what it does not

rolekeeper changes access to your cluster, so the question that matters is who
can make it act.

- It acts only on a bundle that is signed by a key in the key set that the
  offline root key of the RunOS identity service signed. The root key is pinned
  in the trust file that the platform writes when it installs the pod.
- It refuses a bundle for another account or another cluster, a bundle below
  the version floor that it stored, and a first bundle that does not come with a
  fresh signed token.
- It does not trust the carrier. The platform copies the signed bytes into
  ConfigMaps. A person who can write those ConfigMaps can withhold a bundle or
  delay one. That person cannot make rolekeeper apply an object that RunOS did
  not sign.
- It does not call RunOS. There is no address, token or certificate for RunOS in
  the pod.

### What a compromise of the pod would give

The pod's ClusterRole is narrow on purpose (see [deploy/relay.yaml](deploy/relay.yaml)).
It reads and writes ClusterRoles and RoleBindings, patches namespaces and the
two admission policy objects, and impersonates two reserved canary users. It
can bind and escalate only the five RunOS roles. It has no access to Secrets or
pods, and a network policy limits it to the API server and DNS. The admission
policy that implements the deny list matches people (user names that start with
`runos:u:`), not the pod, so the pod cannot use its own policy to lock itself in.

### Limits

- Someone who holds cluster-admin on your cluster can change anything that
  rolekeeper manages. rolekeeper puts its objects back and reports the drift; it
  does not stop an administrator.
- The deny list guards people who authenticate through the RunOS identity
  service. It does not guard service accounts or other identity providers.
- Signing and key custody happen in RunOS, not here. This repository holds the
  verifying side only.

## Release integrity

The container image that a cluster runs is tied to this repository's release
pipeline.

1. **Build-provenance attestation.** The release workflow
   (`.github/workflows/release.yml`) runs `actions/attest-build-provenance`,
   which issues a keyless Sigstore attestation for every released image. It
   binds the image digest to the workflow's OIDC identity. No long-lived signing
   secret exists. Verify with:

   ```sh
   gh attestation verify oci://ghcr.io/runos-official/rolekeeper@sha256:<digest> \
     --repo runos-official/rolekeeper
   ```

2. **A bill of materials.** BuildKit attaches an SPDX software bill of
   materials and a build record to the image index.

3. **Stable and candidate tags.** Only a stable tag moves `latest`. A tag with
   a suffix (for example `v0.2.0-rc.1`) is published and can be pinned by exact
   version, but never becomes `latest`.

4. **Standing gates before a merge.** CI runs on every pull request and every
   push to `dev` and `main`: formatting, `go vet`, the tests with the race
   detector, the coverage floors, `staticcheck`, `govulncheck`, a scan of the
   files, the file names and the commit messages for credentials and internal
   references, and `gitleaks` over the history. A release is cut only from a
   commit that passed them.

### What attestation does not guarantee

Attestation proves that an artifact came from this workflow. It does not prove
that the artifact is benign. A subverted workflow, or malicious code that reached
the release branch, would produce a validly attested image. Repository access
control is the defence against that, and the checklist below is part of it.

### Pinned actions

Every `uses:` in the workflows names a full 40-character commit SHA with a
trailing version comment. A moved tag on a third-party action cannot swap in
other code. Pin any new action the same way before it is merged.

### Checklist for the repository administrators

These controls cannot be enforced by files in this repository.

- [ ] Branch protection on the release branch: require pull requests, block
  direct pushes and force pushes.
- [ ] Required review: at least one approving review before a merge.
- [ ] Restrict who can edit `.github/workflows/` and tighten the repository's
  Actions permissions.
- [ ] Restrict who can push `v*` tags: a tag starts the release workflow and
  decides what is published.
- [ ] Check that the `rolekeeper` package on `ghcr.io` is public after the first
  release.
