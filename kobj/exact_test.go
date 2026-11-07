package kobj_test

import (
	"encoding/json"
	"testing"

	"github.com/runos-official/rolekeeper/kobj"
)

type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func exactOps(t *testing.T, o kobj.Object) []patchOp {
	t.Helper()
	b, ok := o.ExactPatch()
	if !ok {
		t.Fatalf("%s: no exact patch", o.Key())
	}
	var ops []patchOp
	if err := json.Unmarshal(b, &ops); err != nil {
		t.Fatalf("%s: %v: %s", o.Key(), err, b)
	}
	return ops
}

// A server-side apply keeps a list entry that another field manager added
// (a hand-added match condition switches the deny policy off). The exact
// patch sets the whole spec, so no foreign entry can stay.
func TestExactPatchSetsTheWholeSpecOfTheDenyPolicyAndBinding(t *testing.T) {
	for _, kind := range []string{kobj.KindVAP, kobj.KindVAPBinding} {
		spec := map[string]any{"matchConditions": []any{map[string]any{"name": "runos-person", "expression": "true"}}}
		ops := exactOps(t, kobj.Object{Kind: kind, Name: "runos-deny-writes", Spec: spec})
		if len(ops) != 1 || ops[0].Op != "add" || ops[0].Path != "/spec" {
			t.Fatalf("%s: ops %+v", kind, ops)
		}
		got, _ := json.Marshal(ops[0].Value)
		want, _ := json.Marshal(spec)
		if string(got) != string(want) {
			t.Fatalf("%s: spec %s, want %s", kind, got, want)
		}
	}
	// A spec that is not set is written as an empty object, never null.
	ops := exactOps(t, kobj.Object{Kind: kobj.KindVAP, Name: "p"})
	if v, ok := ops[0].Value.(map[string]any); !ok || len(v) != 0 {
		t.Fatalf("empty spec written as %#v", ops[0].Value)
	}
}

// The deny list ConfigMap: data and binaryData are maps, and an apply keeps
// a key that another manager added. The exact patch sets both whole.
func TestExactPatchSetsTheWholeDataOfAConfigMap(t *testing.T) {
	ops := exactOps(t, kobj.Object{Kind: kobj.KindConfigMap, Namespace: "runos", Name: "runos-deny-writes",
		Data: map[string]string{"p1": "x"}})
	if len(ops) != 2 || ops[0].Path != "/data" || ops[1].Path != "/binaryData" || ops[0].Op != "add" || ops[1].Op != "add" {
		t.Fatalf("ops %+v", ops)
	}
	if d, _ := ops[0].Value.(map[string]any); len(d) != 1 || d["p1"] != "x" {
		t.Fatalf("data %#v", ops[0].Value)
	}
	if b, ok := ops[1].Value.(map[string]any); !ok || len(b) != 0 {
		t.Fatalf("binaryData %#v", ops[1].Value)
	}
}

// RBAC rules and subjects are atomic lists: the server-side apply already
// replaces them whole, and a Namespace is never replaced whole.
func TestNoExactPatchWhereTheApplyIsAlreadyExact(t *testing.T) {
	for _, kind := range []string{kobj.KindClusterRole, kobj.KindRoleBinding, kobj.KindClusterRoleBinding, kobj.KindNamespace} {
		if b, ok := (kobj.Object{Kind: kind, Name: "x"}).ExactPatch(); ok || b != nil {
			t.Errorf("%s: exact patch %s", kind, b)
		}
	}
}
