# rolekeeper

rolekeeper is the in-cluster component that keeps Kubernetes RBAC roles and
the deny list in line with the access decisions that RunOS's identity service
(roid) signs.

It runs as one pod, in its own namespace, on a cluster that RunOS manages. You
do not install it by hand: the RunOS platform installs it when you switch on
Kubernetes access for a cluster, and removes it when you switch access off.
This repository is the source of that pod and the place where you can check
what it does.

## What it does

When an administrator grants or removes access to a namespace in RunOS, RunOS
signs the result as a **bundle**: the RoleBindings, the five fixed RunOS
ClusterRoles, the Pod Security labels and the deny list for that cluster.
rolekeeper:

1. Reads the signed bundle from a ConfigMap in its own namespace. The RunOS
   platform writes the ConfigMap. rolekeeper never contacts RunOS.
2. Checks the signature, the account, the cluster and the version (see
   [the security model](#security-model)).
3. Applies the bundle with server-side apply over the Kubernetes API: the deny
   list first, then the removals, then the new objects.
4. Removes the objects that it manages and the bundle no longer holds. It
   touches only objects that carry the label `runos.com/roid-managed=true`,
   and bindings that name a `runos:` subject.
5. Writes a status ConfigMap that the platform reads.

The **deny list** is a ConfigMap (`runos-deny-writes` in the `runos`
namespace) and a ValidatingAdmissionPolicy that refuses every write by a
listed person. A revoke reaches the cluster as a change to that list, so it
takes effect at once and does not wait for a binding to be pruned.

After each pass rolekeeper runs a **deny canary**. It asks the API server, with
a dry-run write as two reserved users, whether the policy still refuses the
listed one and allows the other. If the policy has gone blind, the status says
so.

When RunOS retires a cluster from an account, it signs a retire bundle.
rolekeeper then removes everything it manages and stops. If RunOS keeps
refusing the cluster for longer than a fixed bound, rolekeeper does the same
on its own.

## Security model

rolekeeper acts on bundles that RunOS signed. Everything it acts on is
checked; nothing is trusted because of where it came from.

- **Pinned trust.** The pod starts with a trust file that names the offline
  root key of the RunOS identity service. The offline root signs the set of
  keys that may sign bundles. The root can hand over to a new key; the pod
  follows a signed handover chain and never goes back to an older one.
- **A version floor.** rolekeeper stores the highest bundle version that it
  applied. It refuses a bundle below that floor, so an old, signed bundle
  cannot bring back a binding that a later bundle revoked.
- **No replay.** After a restart without a floor, the first bundle must come
  with a fresh signed token that answers a nonce the pod chose at start. The
  token names the content digest of the bundle, so an older bundle never
  matches.
- **Account and cluster.** A bundle for another account or another cluster is
  refused, whoever signed it.
- **Narrow RBAC.** The pod's own ClusterRole lets it handle only the objects a
  bundle holds. It can bind and escalate only the five RunOS roles. It holds no
  Secrets, no pods, no cluster-wide ConfigMaps and no `watch`. It cannot
  create or delete the deny policy. The reference manifest is
  [deploy/relay.yaml](deploy/relay.yaml); read the rules there.
- **Narrow network.** The pod may reach the API server and DNS, and nothing
  else. It has no ingress. See [deploy/cilium.yaml](deploy/cilium.yaml) for the
  Cilium rule.
- **Hardened pod.** Non-root user 65532, read-only root file system, all
  capabilities dropped, the runtime default seccomp profile.
- **A guard that is checked.** The deny canary (above) tests the deny list
  against the API server after every pass.

Read [SECURITY.md](SECURITY.md) for what this does and does not protect
against, and for how to report a vulnerability.

## Verify an image

Every released image carries a build-provenance attestation signed with
Sigstore, bound to this repository's release workflow. A pod manifest should
name the image by digest.

```sh
gh attestation verify oci://ghcr.io/runos-official/rolekeeper@sha256:<digest> \
  --repo runos-official/rolekeeper
```

The digest of each release is in the summary of its
[release workflow run](https://github.com/runos-official/rolekeeper/actions)
and in the pod spec of your cluster:

```sh
kubectl -n roid-k8s-applier get deployment roid-k8s-applier \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

The image also carries a software bill of materials:

```sh
docker buildx imagetools inspect ghcr.io/runos-official/rolekeeper:<version> \
  --format '{{ json .SBOM }}'
```

## Build it yourself

```sh
make build      # a static binary, ./rolekeeper
make test       # the tests, with the race detector
make image      # the container image for this machine's architecture
```

The binary is built with `-trimpath` and without version-control stamping.
`rolekeeper --version` prints the version and `rolekeeper --help` the main
settings. The binary takes no other argument: it reads its configuration from
the environment, and the full list of variables is at the top of
[cmd/rolekeeper/main.go](cmd/rolekeeper/main.go).

## Go packages

The module `github.com/runos-official/rolekeeper` is a library as well as a binary: RunOS imports its
packages. They sit at the top level of the module, with no `internal`
directory, so any module can import them. The API is **v0**: the packages are
shared with RunOS and may change between minor versions.

| Package | What it holds |
|---|---|
| `applier` | The loop of the pod: reads the bundle, verifies it, applies it, reports status, and runs the retire fail-safe |
| `bundle` | The signed bundle envelope, its content digest, the verifier, the version floor and the relay tokens |
| `compile` | The Kubernetes objects of RunOS access (roles, bindings, labels, the deny list) and the lint that checks them |
| `deploy` | The reference manifests (`relay.yaml`, `cilium.yaml`, `deny-policy.json`), embedded as bytes |
| `kobj` | The small Kubernetes object model and the RunOS label keys |
| `kubeapi` | A minimal Kubernetes API client |
| `reconcile` | Applies objects with server-side apply and repairs drift |
| `signer` | The signing purposes, token lifetimes and the custody backend interface |
| `signer/jws` | Compact JWS with a strict header policy |
| `signer/keys` | The per-purpose key sets: rotation, root-signed reset, the verifier's view |
| `signer/revlog` | The hash-chained revocation log |
| `signer/roottrust` | The offline root pins, the handover chain and the baked-in floors |
| `signer/token` | Token issue and verification |
| `cmd/rolekeeper` | The binary |

## Where this code comes from

This repository is **generated** from the RunOS source tree. The file
[SOURCE](SOURCE) records the commit that produced it and a hash of every other
file. `python3 scripts/treehash.py --check` recomputes the hash, so a hand
edit shows. Pull requests cannot be merged here; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [SECURITY.md](SECURITY.md): the trust model and how to report a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes reach this repository
- [CHANGELOG.md](CHANGELOG.md): release history
- [deploy/](deploy): the reference manifests the pod is installed from

## License

rolekeeper is **source-available** under the [Elastic License 2.0](LICENSE):
the source is published for transparency and security review, not as open
source. Use is subject to the license terms. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Copyright 2026 RunOS.
