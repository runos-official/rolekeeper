package deploy_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/deploy"
)

// rule is one RBAC rule of a Role or ClusterRole in relay.yaml.
type rule struct {
	Kind, Name    string
	APIGroups     []string
	Resources     []string
	Verbs         []string
	ResourceNames []string
}

// relayRules returns every rule of every Role and ClusterRole in relay.yaml.
// relay.yaml writes each rule field as a flow list (["a", "b"]), which is
// also JSON. The parser fails on any other shape, so a rule it cannot read
// fails the test instead of passing unread.
func relayRules(t *testing.T) []rule {
	t.Helper()
	var out []rule
	for _, doc := range strings.Split(string(deploy.Relay), "\n---\n") {
		lines := strings.Split(doc, "\n")
		kind, name := "", ""
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, "kind: "); ok {
				kind = v
			}
			if v, ok := strings.CutPrefix(l, "  name: "); ok && name == "" {
				name = v
			}
		}
		if kind != "Role" && kind != "ClusterRole" {
			continue
		}
		in := false
		for _, l := range lines {
			if l == "rules:" {
				in = true
				continue
			}
			if !in || strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			field := l
			switch {
			case strings.HasPrefix(l, "  - "):
				out = append(out, rule{Kind: kind, Name: name})
				field = strings.TrimPrefix(l, "  - ")
			case strings.HasPrefix(l, "    "):
				field = strings.TrimPrefix(l, "    ")
			default:
				t.Fatalf("%s %s: a line in rules that the test cannot read: %q", kind, name, l)
			}
			if len(out) == 0 {
				t.Fatalf("%s %s: a rule field before the first rule: %q", kind, name, l)
			}
			key, val, ok := strings.Cut(field, ": ")
			var list []string
			if !ok || json.Unmarshal([]byte(val), &list) != nil {
				t.Fatalf("%s %s: a rule field that is not a flow list: %q", kind, name, l)
			}
			r := &out[len(out)-1]
			switch key {
			case "apiGroups":
				r.APIGroups = list
			case "resources":
				r.Resources = list
			case "verbs":
				r.Verbs = list
			case "resourceNames":
				r.ResourceNames = list
			default:
				t.Fatalf("%s %s: an unknown rule field %q", kind, name, key)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("relay.yaml holds no RBAC rule")
	}
	return out
}

// The pod may change only the admission objects that it owns: the deny
// policy and its binding, both named compile.DenyPolicyName. An unnamed
// patch would let the pod rewrite any admission policy on the cluster,
// including a guard that an installer puts in front of the pod's own
// writes. Kubernetes cannot limit list to a name, so get and list stay
// cluster-wide; the pod reads, and changes only its own two objects.
func TestThePodChangesOnlyItsOwnAdmissionObjects(t *testing.T) {
	read := []string{"get", "list"}
	own := []string{compile.DenyPolicyName}
	admission := []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}
	var repair bool
	for _, r := range relayRules(t) {
		if !slices.Contains(r.APIGroups, "admissionregistration.k8s.io") && !slices.Contains(r.APIGroups, "*") {
			continue
		}
		if slices.Contains(r.Resources, "*") || slices.Contains(r.Verbs, "*") {
			t.Errorf("%s %s: a wildcard on admission objects: %+v", r.Kind, r.Name, r)
			continue
		}
		for _, res := range r.Resources {
			if !slices.Contains(admission, res) {
				t.Errorf("%s %s: the pod may touch admission resource %q", r.Kind, r.Name, res)
			}
		}
		var writes []string
		for _, v := range r.Verbs {
			if !slices.Contains(read, v) {
				writes = append(writes, v)
			}
		}
		if len(writes) == 0 {
			continue
		}
		if !slices.Equal(writes, []string{"patch"}) {
			t.Errorf("%s %s: admission verbs %v, the pod may only patch (no create, update or delete)", r.Kind, r.Name, writes)
		}
		if !slices.Equal(r.ResourceNames, own) {
			t.Errorf("%s %s: admission %v on names %v, want only %v", r.Kind, r.Name, writes, r.ResourceNames, own)
			continue
		}
		if slices.Contains(r.Resources, admission[0]) && slices.Contains(r.Resources, admission[1]) {
			repair = true
		}
	}
	if !repair {
		t.Errorf("no rule lets the pod patch %s (policy and binding): the in-place repair would fail", compile.DenyPolicyName)
	}
}

// The parser above must see the rules that matter. If relay.yaml changes
// its layout, this test fails before the one above passes on nothing.
func TestTheRBACParserSeesThePodRules(t *testing.T) {
	var admission, impersonate bool
	for _, r := range relayRules(t) {
		if slices.Contains(r.APIGroups, "admissionregistration.k8s.io") {
			admission = true
		}
		if slices.Contains(r.Verbs, "impersonate") {
			impersonate = true
		}
	}
	if !admission || !impersonate {
		t.Errorf("the parser missed rules: admission %v, impersonate %v", admission, impersonate)
	}
}
