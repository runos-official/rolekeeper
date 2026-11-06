// Package deploy embeds the reference manifests the pod is installed from, so
// that a caller reads them as bytes and not from a path in the module cache.
//
// relay.yaml holds the namespace, accounts, roles, network policy and
// Deployment of the pod, with placeholders the installer fills.
// cilium.yaml is the extra CiliumNetworkPolicy for clusters that run Cilium.
// deny-policy.json is the deny policy the pod keeps.
//
// The API of this package is v0 and may change between minor versions.
package deploy

import "embed"

// Relay is the reference manifest of the pod (relay transport).
//
//go:embed relay.yaml
var Relay []byte

// Cilium is the CiliumNetworkPolicy that goes with Relay on a Cilium cluster.
//
//go:embed cilium.yaml
var Cilium []byte

// DenyPolicy is the deny policy, as JSON.
//
//go:embed deny-policy.json
var DenyPolicy []byte

// Files holds the three files under their names.
//
//go:embed relay.yaml cilium.yaml deny-policy.json
var Files embed.FS
