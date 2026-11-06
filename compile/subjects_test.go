package compile_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

var fixedNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func TestSubjectNamesAreBuiltAndSplitBackToTheirParts(t *testing.T) {
	if got := compile.GroupSubject("ops", compile.RoleEdit); got != "runos:g:ops:edit" {
		t.Fatalf("group subject %q", got)
	}
	if got := compile.PersonRoleSubject("alice", "runos:view"); got != "runos:u:alice:view" {
		t.Fatalf("person subject %q", got)
	}
	if got := compile.ClusterWideGroup(compile.RoleNSAdmin); got != "runos:cw:ns-admin" {
		t.Fatalf("cluster-wide group %q", got)
	}
	if got := compile.ShortRole(compile.RoleSecretsRead); got != "secrets-read" {
		t.Fatalf("short role %q", got)
	}
	g, role, ok := compile.SplitGroupSubject("runos:g:ops.team:exec")
	if !ok || g != "ops.team" || role != "exec" {
		t.Fatalf("split group: %q %q %v", g, role, ok)
	}
	p, role, ok := compile.SplitPersonRoleSubject("runos:u:alice:view")
	if !ok || p != "alice" || role != "view" {
		t.Fatalf("split person: %q %q %v", p, role, ok)
	}
}

func TestSplitRefusesASubjectOfTheWrongShape(t *testing.T) {
	for _, s := range []string{"", "runos:u:alice", "runos:cw:view", "alice:view", "runos:g:nocolon"} {
		if _, _, ok := compile.SplitGroupSubject(s); ok {
			t.Errorf("SplitGroupSubject(%q) accepted", s)
		}
	}
	for _, s := range []string{"", "runos:u:alice", "runos:g:ops:view", "alice:view"} {
		if _, _, ok := compile.SplitPersonRoleSubject(s); ok {
			t.Errorf("SplitPersonRoleSubject(%q) accepted", s)
		}
	}
}

func TestValidSubjectID(t *testing.T) {
	ok := []string{"a", "alice", "a1", "ops.team", "ops-team", "0abc", strings.Repeat("a", 63)}
	bad := []string{"", "Alice", "-a", "a-", ".a", "a.", "a:b", "a/b", "a b", "a_b", strings.Repeat("a", 64)}
	for _, id := range ok {
		if !compile.ValidSubjectID(id) {
			t.Errorf("%q refused", id)
		}
	}
	for _, id := range bad {
		if compile.ValidSubjectID(id) {
			t.Errorf("%q accepted", id)
		}
	}
}

func TestBindingNamesAreDeterministicPerRoleAndSubject(t *testing.T) {
	cases := []struct{ role, subject, want string }{
		{compile.RoleView, "runos:g:ops:view", "runos:view:g:ops"},
		{compile.RoleEdit, "runos:u:alice:edit", "runos:edit:u:alice"},
		{compile.RoleView, "runos:cw:view", "runos:view:cw"},
		{compile.RoleView, "runos:u:bare", "runos:view:u:bare"},
		{compile.RoleView, "other", "runos:view:other"},
	}
	for _, c := range cases {
		if got := compile.BindingName(c.role, c.subject); got != c.want {
			t.Errorf("BindingName(%q, %q) = %q, want %q", c.role, c.subject, got, c.want)
		}
	}
}

func TestSystemNamespacesAreProtected(t *testing.T) {
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease", "default", "runos", "local-path-storage", compile.ApplierNamespace, "kube-anything"} {
		if !compile.IsSystemNamespace(ns) {
			t.Errorf("%q is not protected", ns)
		}
	}
	for _, ns := range []string{"apps", "team-a", "kubernetes", "runos-apps"} {
		if compile.IsSystemNamespace(ns) {
			t.Errorf("%q is protected", ns)
		}
	}
}

func TestProtectedNamespaceCELNamesEveryProtectedNamespace(t *testing.T) {
	expr := compile.ProtectedNamespaceCEL("request.namespace")
	for _, ns := range compile.SystemNamespaces {
		if !strings.Contains(expr, "'"+ns+"'") {
			t.Errorf("expression does not name %s: %s", ns, expr)
		}
	}
	if !strings.Contains(expr, "startsWith('"+compile.ProtectedPrefix+"')") {
		t.Errorf("expression does not hold the prefix rule: %s", expr)
	}
}

func TestOnlyTheFiveFixedRolesAreFixed(t *testing.T) {
	for _, r := range []string{compile.RoleView, compile.RoleEdit, compile.RoleExec, compile.RoleNSAdmin, compile.RoleSecretsRead} {
		if !compile.IsFixedRole(r) {
			t.Errorf("%s is not fixed", r)
		}
	}
	for _, r := range []string{"view", "admin", "cluster-admin", "runos:breakglass", ""} {
		if compile.IsFixedRole(r) {
			t.Errorf("%q is fixed", r)
		}
	}
}

func TestEveryActionMapsToOneFixedRole(t *testing.T) {
	seen := map[string]bool{}
	for _, ar := range compile.ActionRoles {
		if !compile.IsFixedRole(ar.Role) {
			t.Errorf("%s maps to %s, which is not fixed", ar.Action, ar.Role)
		}
		if seen[ar.Role] {
			t.Errorf("role %s is mapped twice", ar.Role)
		}
		seen[ar.Role] = true
	}
	if len(seen) != 5 {
		t.Fatalf("%d roles mapped, want 5", len(seen))
	}
}

func TestVersionRendersAsALabelValue(t *testing.T) {
	for v, want := range map[uint64]string{0: "pv-0", 7: "pv-7", 1234567890: "pv-1234567890", 18446744073709551615: "pv-18446744073709551615"} {
		if got := compile.Version(v); got != want {
			t.Errorf("Version(%d) = %q, want %q", v, got, want)
		}
	}
}

func TestErrorTextNamesTheCodeAndTheGrant(t *testing.T) {
	var err error = &compile.Error{Code: "policy.invalid", Grant: "g1", Reason: "bad"}
	if got := err.Error(); got != "policy.invalid grant=g1: bad" {
		t.Fatalf("got %q", got)
	}
	var ce *compile.Error
	if !errors.As(err, &ce) || ce.Code != "policy.invalid" {
		t.Fatal("not a compile.Error")
	}
}

func TestClaimRulesAreOneListInAFixedOrder(t *testing.T) {
	claim := compile.ClaimValidationRules()
	if len(claim) != 6 {
		t.Fatalf("%d claim rules, want 6", len(claim))
	}
	wantFirst := []string{compile.PurposeRule, compile.ClassRule, compile.JTIRule, compile.LifetimeRule, compile.UsernameRule, compile.ClaimGroupsRule}
	for i, r := range claim {
		if r.Expression != wantFirst[i] || r.Message == "" {
			t.Errorf("claim rule %d: %+v", i, r)
		}
	}
	user := compile.UserValidationRules()
	if len(user) != 2 || user[0].Expression != compile.NoSystemUserRule || user[1].Expression != compile.NoSystemGroupRule {
		t.Fatalf("user rules: %+v", user)
	}
}

func TestClaimGroupsRuleNamesTheFiveRolesAndNoOther(t *testing.T) {
	for _, r := range []string{"view", "edit", "exec", "ns-admin", "secrets-read"} {
		if !strings.Contains(compile.ClaimGroupsRule, r) {
			t.Errorf("rule does not name %s", r)
		}
	}
	if strings.Contains(compile.ClaimGroupsRule, "cluster-admin") {
		t.Error("rule names cluster-admin")
	}
}

func TestFixedRolesAreFiveAndCarryTheLabels(t *testing.T) {
	roles := compile.FixedRoles(testVersion, testAccount)
	var names []string
	for _, r := range roles {
		names = append(names, r.Name)
		if r.Labels[kobj.LabelManaged] != "true" || r.Labels[kobj.LabelPolicyVersion] != testVersion || r.Labels[kobj.LabelAccount] != testAccount {
			t.Errorf("%s labels %v", r.Name, r.Labels)
		}
	}
	slices.Sort(names)
	want := []string{"runos:edit", "runos:exec", "runos:ns-admin", "runos:secrets-read", "runos:view"}
	if !slices.Equal(names, want) {
		t.Fatalf("roles %v, want %v", names, want)
	}
}

func TestOnlyTheExecRoleHoldsStreamSubresources(t *testing.T) {
	for _, r := range compile.FixedRoles(testVersion, testAccount) {
		for _, rule := range r.Rules {
			for _, res := range rule.Resources {
				stream := res == "pods/exec" || res == "pods/attach" || res == "pods/portforward" || res == "pods/ephemeralcontainers"
				if stream && r.Name != compile.RoleExec {
					t.Errorf("%s holds %s", r.Name, res)
				}
			}
		}
	}
}

func TestNoFixedRoleWritesBindings(t *testing.T) {
	for _, r := range compile.FixedRoles(testVersion, testAccount) {
		for _, rule := range r.Rules {
			if !slices.Contains(rule.Resources, "rolebindings") {
				continue
			}
			for _, verb := range []string{"create", "update", "patch", "bind", "escalate", "*"} {
				if slices.Contains(rule.Verbs, verb) {
					t.Errorf("%s may %s rolebindings", r.Name, verb)
				}
			}
		}
	}
}
