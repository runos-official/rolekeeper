package compile

// The break-glass group runos:breakglass is
// bound to a defined break-glass ClusterRole, not cluster-admin. The role
// reads everything except Secrets, and holds only what restores access:
// RBAC writes, a bind on the fixed RunOS roles, the
// removal of a broken webhook, and the deny-list ConfigMap. A guard
// ValidatingAdmissionPolicy keeps those writes out of protected namespaces.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/internal/kobj"
)

func bgObjects(t *testing.T) (role kobj.Object, crb kobj.Object, all []kobj.Object) {
	t.Helper()
	all = BreakGlassObjects("pv-1")
	for _, o := range all {
		switch {
		case o.Kind == kobj.KindClusterRole && o.Name == RoleBreakGlass:
			role = o
		case o.Kind == kobj.KindClusterRoleBinding && o.Name == RoleBreakGlass:
			crb = o
		}
	}
	if role.Name == "" || crb.Name == "" {
		t.Fatalf("break-glass ClusterRole or ClusterRoleBinding missing: %d objects", len(all))
	}
	return role, crb, all
}

// allows reports whether the rules allow verb on group/resource (name "" is
// a request with no name, such as create or list).
func allows(rules []kobj.Rule, verb, group, resource, name string) bool {
	for _, r := range rules {
		if !slices.Contains(r.Verbs, verb) && !slices.Contains(r.Verbs, "*") {
			continue
		}
		if !slices.Contains(r.APIGroups, group) && !slices.Contains(r.APIGroups, "*") {
			continue
		}
		if !slices.Contains(r.Resources, resource) && !slices.Contains(r.Resources, "*") {
			continue
		}
		if len(r.ResourceNames) > 0 && !slices.Contains(r.ResourceNames, name) {
			continue
		}
		return true
	}
	return false
}

func TestBreakGlassGroupIsNotClusterAdmin(t *testing.T) {
	_, crb, _ := bgObjects(t)
	if crb.RoleRef == nil || crb.RoleRef.Name != RoleBreakGlass {
		t.Fatalf("runos:breakglass binds %+v, want ClusterRole %s", crb.RoleRef, RoleBreakGlass)
	}
	if len(crb.Subjects) != 1 || crb.Subjects[0].Kind != "Group" || crb.Subjects[0].Name != BreakGlassGroup {
		t.Fatalf("subjects %+v, want only Group %s", crb.Subjects, BreakGlassGroup)
	}
}

func TestBreakGlassRoleReadsEverythingButSecrets(t *testing.T) {
	role, _, _ := bgObjects(t)
	for _, r := range role.Rules {
		for _, f := range [][]string{r.APIGroups, r.Resources, r.Verbs} {
			if slices.Contains(f, "*") {
				t.Fatalf("wildcard in %+v: a wildcard read includes Secrets", r)
			}
		}
		if slices.Contains(r.Resources, "secrets") {
			t.Fatalf("secrets appear in %+v", r)
		}
	}
	reads := [][2]string{
		{"", "pods"}, {"", "pods/log"}, {"", "nodes"}, {"", "namespaces"}, {"", "configmaps"}, {"", "serviceaccounts"},
		{"", "events"}, {"", "persistentvolumes"}, {"apps", "deployments"}, {"apps", "daemonsets"}, {"batch", "jobs"},
		{"networking.k8s.io", "networkpolicies"}, {"rbac.authorization.k8s.io", "clusterrolebindings"},
		{"admissionregistration.k8s.io", "validatingadmissionpolicies"}, {"admissionregistration.k8s.io", "mutatingwebhookconfigurations"},
		{"apiextensions.k8s.io", "customresourcedefinitions"}, {"storage.k8s.io", "storageclasses"}, {"policy", "poddisruptionbudgets"},
	}
	for _, gr := range reads {
		for _, v := range []string{"get", "list", "watch"} {
			if !allows(role.Rules, v, gr[0], gr[1], "") {
				t.Errorf("break-glass cannot %s %s/%s", v, gr[0], gr[1])
			}
		}
	}
}

func TestBreakGlassRoleHoldsOnlyRestoreWrites(t *testing.T) {
	role, _, _ := bgObjects(t)
	rbac := "rbac.authorization.k8s.io"
	adm := "admissionregistration.k8s.io"
	for _, res := range []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
		for _, v := range []string{"create", "update", "patch", "delete"} {
			if !allows(role.Rules, v, rbac, res, "x") {
				t.Errorf("break-glass cannot %s %s", v, res)
			}
		}
	}
	for _, fixed := range fixedRoleNames {
		if !allows(role.Rules, "bind", rbac, "clusterroles", fixed) {
			t.Errorf("break-glass cannot bind %s, so it cannot restore a person's grant", fixed)
		}
	}
	for _, other := range []string{"cluster-admin", "admin", "edit", "system:node", RoleBreakGlass, ""} {
		if allows(role.Rules, "bind", rbac, "clusterroles", other) {
			t.Errorf("break-glass may bind %q", other)
		}
	}
	for _, v := range []string{"escalate", "impersonate", "approve", "sign"} {
		for _, r := range role.Rules {
			if slices.Contains(r.Verbs, v) {
				t.Errorf("verb %s in %+v", v, r)
			}
		}
	}
	// No admission-policy write at all. Admission
	// never runs on admission-policy objects, so no guard can bound them. The
	// old test expected a create right and deny-list updates; it pinned the
	// behaviour found to be a cluster-wide freeze.
	for _, res := range []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"} {
		for _, v := range []string{"create", "update", "patch", "delete"} {
			for _, n := range []string{"", DenyListPolicyName, BreakGlassGuardName, "x"} {
				if allows(role.Rules, v, adm, res, n) {
					t.Errorf("break-glass may %s %s %q", v, res, n)
				}
			}
		}
	}
	for _, res := range []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"} {
		if !allows(role.Rules, "delete", adm, res, "x") {
			t.Errorf("break-glass cannot delete a broken %s", res)
		}
		for _, v := range []string{"create", "update", "patch"} {
			if allows(role.Rules, v, adm, res, "x") {
				t.Errorf("break-glass may %s %s: a webhook can rewrite any object", v, res)
			}
		}
	}
	// Workload writes, exec and token minting stay out.
	for _, c := range [][3]string{
		{"create", "apps", "deployments"}, {"create", "", "pods"}, {"create", "", "pods/exec"}, {"get", "", "pods/exec"},
		{"create", "", "serviceaccounts/token"}, {"create", "certificates.k8s.io", "certificatesigningrequests"},
		{"get", "", "nodes/proxy"}, {"update", "", "configmaps"}, {"delete", "", "namespaces"},
	} {
		if allows(role.Rules, c[0], c[1], c[2], "") {
			t.Errorf("break-glass may %s %s/%s", c[0], c[1], c[2])
		}
	}
}

func TestBreakGlassEditsOnlyTheDenyListConfigMap(t *testing.T) {
	_, _, all := bgObjects(t)
	var rb kobj.Object
	var cr kobj.Object
	for _, o := range all {
		if o.Kind == kobj.KindRoleBinding && o.Namespace == DenyListNamespace {
			rb = o
		}
		if o.Kind == kobj.KindClusterRole && o.Name == RoleBreakGlassDenyList {
			cr = o
		}
	}
	if rb.Name == "" || cr.Name == "" {
		t.Fatal("no namespaced grant for the deny-list ConfigMap")
	}
	if rb.RoleRef == nil || rb.RoleRef.Name != RoleBreakGlassDenyList || rb.Subjects[0].Name != BreakGlassGroup {
		t.Fatalf("deny-list binding %+v", rb)
	}
	for _, v := range []string{"get", "update", "patch"} {
		if !allows(cr.Rules, v, "", "configmaps", DenyListConfigMap) {
			t.Errorf("break-glass cannot %s the deny-list ConfigMap", v)
		}
	}
	if allows(cr.Rules, "update", "", "configmaps", "other") || allows(cr.Rules, "create", "", "configmaps", "") {
		t.Error("deny-list grant reaches other ConfigMaps")
	}
}

func TestBreakGlassGuardKeepsRBACWritesOutOfProtectedNamespaces(t *testing.T) {
	m := BreakGlassGuard()
	b, _ := json.Marshal(m)
	s := string(b)
	for _, want := range []string{
		`"kind":"ValidatingAdmissionPolicy"`, `"kind":"ValidatingAdmissionPolicyBinding"`,
		`"failurePolicy":"Fail"`, BreakGlassGroup, "kube-system", "kube-", "ClusterRoleBinding", BreakGlassStamp,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("guard lacks %q", want)
		}
	}
	// Measured on 1.36.4: a cluster-scoped request has no
	// request.namespace key, so the guard must test presence first ("no
	// such key: namespace" refused every ClusterRoleBinding delete).
	if !strings.Contains(s, "!has(request.namespace)") {
		t.Error("guard reads request.namespace without has(): cluster-scoped requests error out")
	}
	for _, ns := range SystemNamespaces {
		if !strings.Contains(s, "'"+ns+"'") {
			t.Errorf("guard does not name protected namespace %s", ns)
		}
	}
}

func TestBreakGlassObjectsCarryTheVersionLabel(t *testing.T) {
	_, _, all := bgObjects(t)
	for _, o := range all {
		if o.Labels[kobj.LabelPolicyVersion] != "pv-1" || o.Labels[LabelPlatform] != "breakglass" {
			t.Errorf("%s labels %v", o.Key(), o.Labels)
		}
	}
}
