package compile

import (
	"os"
	"path/filepath"
	"testing"
)

// The installer creates the deny policy, its binding and an empty
// list before the applier starts. Kubernetes lets only a writer who may get
// every ConfigMap in the cluster create a policy whose paramKind is
// ConfigMap (measured on kind v1.36.1: 422 for the applier), and the
// applier holds no cluster-wide ConfigMap read. It updates the list and
// repairs the policy afterwards (an update that keeps paramKind needs no
// such check). The file must be exactly the compiled deny objects, list
// first, so the binding never stands without its list.
func TestDenyInstallFileIsTheCompiledDenyPolicy(t *testing.T) {
	p := filepath.Join("..", "deploy", "deny-policy.json")
	want := DenyInstallList("${ACCOUNT}")
	if os.Getenv("ROID_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(p, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s differs from the compiled deny objects; run with ROID_UPDATE_GOLDEN=1 and review the diff", p)
	}
}

// Measured on kind v1.36.1: with parameterNotFoundAction Deny and the
// list missing, the API server refuses EVERY write that the policy's
// resource rules match, for every user, before matchConditions run (a
// cluster admin's ConfigMap create was refused, and the node lease stopped
// renewing). The applier then cannot recreate the list either. So a missing
// list allows: anyone who can delete the list can delete the binding too,
// and the applier writes the list back in its next pass (deny list first).
func TestDenyBindingAllowsWhenTheListIsMissing(t *testing.T) {
	ref, _ := DenyBindingSpec()["paramRef"].(map[string]any)
	if ref["parameterNotFoundAction"] != "Allow" {
		t.Fatalf("parameterNotFoundAction %v: a missing list would stop every write in the cluster", ref["parameterNotFoundAction"])
	}
}
