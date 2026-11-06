package deploy_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/runos-official/rolekeeper/deploy"
)

func TestEveryFileIsEmbedded(t *testing.T) {
	for name, want := range map[string][]byte{
		"relay.yaml":       deploy.Relay,
		"cilium.yaml":      deploy.Cilium,
		"deny-policy.json": deploy.DenyPolicy,
	} {
		got, err := deploy.Files.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) == 0 {
			t.Errorf("%s is empty", name)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the variable and the file system differ", name)
		}
	}
}

func TestTheManifestsAreTheOnesThePodNeeds(t *testing.T) {
	for name, want := range map[string]string{
		"relay.yaml":  "kind: Deployment",
		"cilium.yaml": "kind: CiliumNetworkPolicy",
	} {
		b, err := deploy.Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("%s does not hold %q", name, want)
		}
	}
	var v map[string]any
	if err := json.Unmarshal(deploy.DenyPolicy, &v); err != nil {
		t.Fatalf("deny-policy.json is not JSON: %v", err)
	}
}
