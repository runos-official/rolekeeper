package compile_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

// lintWith returns the findings for the clean set after mutate has changed it.
func lintWith(t *testing.T, mutate func(objs []kobj.Object) []kobj.Object) []string {
	t.Helper()
	return compile.Lint(mutate(cleanSet()))
}

// find returns the object with this kind and name, so a test can change it in place.
func find(t *testing.T, objs []kobj.Object, kind, name string) *kobj.Object {
	t.Helper()
	for i := range objs {
		if objs[i].Kind == kind && objs[i].Name == name {
			return &objs[i]
		}
	}
	t.Fatalf("no %s %s in the set", kind, name)
	return nil
}

func wantFinding(t *testing.T, findings []string, part string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f, part) {
			return
		}
	}
	t.Fatalf("no finding mentions %q; findings: %q", part, findings)
}

func TestLintAcceptsTheCompiledShape(t *testing.T) {
	if got := compile.Lint(cleanSet()); len(got) != 0 {
		t.Fatalf("a clean set has findings: %q", got)
	}
}

func TestLintAcceptsNothingAtAll(t *testing.T) {
	if got := compile.Lint(nil); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

func TestLintFindingsAreSorted(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		find(t, objs, kobj.KindClusterRole, compile.RoleView).Labels = nil
		find(t, objs, kobj.KindClusterRole, compile.RoleEdit).Labels = nil
		return objs
	})
	if len(got) < 2 || !slices.IsSorted(got) {
		t.Fatalf("findings are not sorted: %q", got)
	}
}

func TestLintRefusesAnObjectWithoutTheMarkerOrTheVersion(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		find(t, objs, kobj.KindClusterRole, compile.RoleView).Labels = map[string]string{kobj.LabelManaged: "true"}
		find(t, objs, kobj.KindNamespace, "apps").Labels[kobj.LabelAccess] = "false"
		return objs
	})
	wantFinding(t, got, "ClusterRole//runos:view: label: missing")
	wantFinding(t, got, "Namespace//apps: label: missing")
}

func TestLintRefusesAnAggregationLabelAndAnAggregationRule(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		r := find(t, objs, kobj.KindClusterRole, compile.RoleView)
		r.Labels["rbac.authorization.k8s.io/aggregate-to-view"] = "true"
		r.Aggregation = true
		return objs
	})
	wantFinding(t, got, "aggregation label")
	wantFinding(t, got, "aggregationRule")
}

func TestLintRefusesAManagedSystemNamespace(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		ns := managedNamespace("kube-system")
		return append(objs, ns)
	})
	wantFinding(t, got, "system namespace is managed")
}

func TestLintRefusesANamespaceWithoutBaselinePodSecurity(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		find(t, objs, kobj.KindNamespace, "apps").Labels["pod-security.kubernetes.io/enforce"] = "privileged"
		return objs
	})
	wantFinding(t, got, `pod security enforce="privileged"`)
	// restricted is stricter than baseline and stays allowed.
	ok := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		find(t, objs, kobj.KindNamespace, "apps").Labels["pod-security.kubernetes.io/enforce"] = "restricted"
		return objs
	})
	if len(ok) != 0 {
		t.Fatalf("restricted refused: %q", ok)
	}
}

func TestLintRefusesAClusterRoleThatIsNotOneOfTheFive(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		extra := kobj.Object{Kind: kobj.KindClusterRole, Name: "runos:custom", Labels: compile.Labels(testVersion, testAccount)}
		return append(objs, extra)
	})
	wantFinding(t, got, "not a fixed RunOS role")
}

func TestLintRefusesEveryEscalationInARole(t *testing.T) {
	cases := []struct {
		name string
		role string
		rule kobj.Rule
		want string
	}{
		{"wildcard verb", compile.RoleView, kobj.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}, "wildcard"},
		{"wildcard resource", compile.RoleView, kobj.Rule{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}}, "wildcard"},
		{"wildcard group", compile.RoleView, kobj.Rule{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"get"}}, "wildcard"},
		{"impersonate", compile.RoleEdit, kobj.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"impersonate"}}, "forbidden verb impersonate"},
		{"bind", compile.RoleNSAdmin, kobj.Rule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"bind"}}, "forbidden verb bind"},
		{"escalate", compile.RoleNSAdmin, kobj.Rule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"escalate"}}, "forbidden verb escalate"},
		{"exec in view", compile.RoleView, kobj.Rule{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}, "stream subresource pods/exec"},
		{"portforward in edit", compile.RoleEdit, kobj.Rule{APIGroups: []string{""}, Resources: []string{"pods/portforward"}, Verbs: []string{"create"}}, "stream subresource"},
		{"service account token", compile.RoleEdit, kobj.Rule{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}}, "forbidden resource"},
		{"nodes", compile.RoleView, kobj.Rule{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get"}}, "forbidden resource nodes"},
		{"cluster roles", compile.RoleNSAdmin, kobj.Rule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"get"}}, "forbidden resource clusterroles"},
		{"webhooks", compile.RoleEdit, kobj.Rule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingwebhookconfigurations"}, Verbs: []string{"delete"}}, "forbidden resource"},
		{"rolebindings in edit", compile.RoleEdit, kobj.Rule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"rolebindings"}, Verbs: []string{"get"}}, "rbac resource rolebindings outside"},
		{"secrets read in view", compile.RoleView, kobj.Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}, "secrets read outside"},
		{"secrets watch in exec", compile.RoleExec, kobj.Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"watch"}}, "secrets read outside"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
				r := find(t, objs, kobj.KindClusterRole, c.role)
				r.Rules = append(slices.Clone(r.Rules), c.rule)
				return objs
			})
			wantFinding(t, got, c.want)
		})
	}
}

func TestLintAllowsWhatTheFixedRolesAreMeantToHold(t *testing.T) {
	// edit writes secrets (no read verb), secrets-read reads them, exec streams,
	// and ns-admin reads and deletes bindings. None of these is a finding.
	if got := compile.Lint(compile.FixedRoles(testVersion, testAccount)); len(got) != 0 {
		t.Fatalf("the fixed roles fail their own lint: %q", got)
	}
}

func TestLintRefusesABindingToAnythingButAFixedClusterRole(t *testing.T) {
	cases := map[string]*kobj.RoleRef{
		"cluster-admin": {APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: "cluster-admin"},
		"a Role":        {APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: compile.RoleView},
		"no roleRef":    nil,
	}
	for name, ref := range cases {
		t.Run(name, func(t *testing.T) {
			got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
				find(t, objs, kobj.KindRoleBinding, "runos:view:g:ops").RoleRef = ref
				return objs
			})
			wantFinding(t, got, "is not a fixed RunOS ClusterRole")
		})
	}
}

func TestLintRefusesAClusterRoleBindingAndABindingInASystemNamespace(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		crb := roleBinding("", compile.RoleView, compile.ClusterWideGroup(compile.RoleView))
		crb.Kind = kobj.KindClusterRoleBinding
		sys := roleBinding("kube-system", compile.RoleView, compile.GroupSubject("ops", compile.RoleView))
		return append(objs, crb, sys)
	})
	wantFinding(t, got, "ClusterRoleBinding is never compiled")
	wantFinding(t, got, "binding in system namespace kube-system")
}

func TestLintRefusesASubjectThatIsNotACompiledGroup(t *testing.T) {
	cases := []struct {
		name    string
		subject kobj.Subject
		role    string
		want    string
	}{
		{"user kind", kobj.Subject{Kind: "User", Name: "runos:u:alice:view"}, compile.RoleView, "not a runos:u"},
		{"service account", kobj.Subject{Kind: "ServiceAccount", Name: "default", Namespace: "apps"}, compile.RoleView, "not a runos:u"},
		{"foreign group", kobj.Subject{Kind: "Group", Name: "system:masters"}, compile.RoleView, "not a runos:u"},
		{"person with a bad id", kobj.Subject{Kind: "Group", Name: "runos:u:Alice:view"}, compile.RoleView, "person id is not a plain name"},
		{"person with no role", kobj.Subject{Kind: "Group", Name: "runos:u:alice"}, compile.RoleView, "person id is not a plain name"},
		{"person names another role", kobj.Subject{Kind: "Group", Name: "runos:u:alice:edit"}, compile.RoleView, "binds only the fixed role it names"},
		{"group with a bad id", kobj.Subject{Kind: "Group", Name: "runos:g:a_b:view"}, compile.RoleView, "group id is not a plain name"},
		{"group names another role", kobj.Subject{Kind: "Group", Name: "runos:g:ops:edit"}, compile.RoleView, "binds only the fixed role it names"},
		{"cluster-wide for another role", kobj.Subject{Kind: "Group", Name: "runos:cw:edit"}, compile.RoleView, "binds only its own fixed role"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
				b := find(t, objs, kobj.KindRoleBinding, "runos:view:g:ops")
				b.Subjects = []kobj.Subject{c.subject}
				b.RoleRef.Name = c.role
				return objs
			})
			wantFinding(t, got, c.want)
		})
	}
}

func TestLintRefusesAKindThatIsNotCompiled(t *testing.T) {
	got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
		return append(objs, kobj.Object{Kind: "Secret", Name: "s", Namespace: "apps", Labels: compile.Labels(testVersion, testAccount)})
	})
	wantFinding(t, got, "kind Secret is not compiled by RunOS")
}

func TestLintChecksTheDenyObjectsAgainstTheCompiledShape(t *testing.T) {
	t.Run("policy spec changed", func(t *testing.T) {
		got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
			p := find(t, objs, kobj.KindVAP, compile.DenyPolicyName)
			p.Spec = map[string]any{"failurePolicy": "Ignore"}
			return objs
		})
		wantFinding(t, got, "admission policy spec differs")
	})
	t.Run("binding spec changed", func(t *testing.T) {
		got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
			b := find(t, objs, kobj.KindVAPBinding, compile.DenyPolicyName)
			b.Spec = map[string]any{"policyName": compile.DenyPolicyName, "validationActions": []string{"Audit"}}
			return objs
		})
		wantFinding(t, got, "admission binding spec differs")
	})
	t.Run("policy under another name", func(t *testing.T) {
		got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
			p := find(t, objs, kobj.KindVAP, compile.DenyPolicyName).Clone()
			p.Name = "other"
			return append(objs, p)
		})
		wantFinding(t, got, "admission policy is not "+compile.DenyPolicyName)
	})
	t.Run("list key is not a person id", func(t *testing.T) {
		got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
			cm := find(t, objs, kobj.KindConfigMap, compile.DenyPolicyName)
			cm.Data = map[string]string{"Not A Person": "2031-01-01T00:00:00Z"}
			return objs
		})
		wantFinding(t, got, "is not a person id")
	})
	t.Run("list entry has no expiry", func(t *testing.T) {
		got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
			cm := find(t, objs, kobj.KindConfigMap, compile.DenyPolicyName)
			cm.Data = map[string]string{"alice": "tomorrow"}
			return objs
		})
		wantFinding(t, got, "has no RFC 3339 expiry")
	})
	t.Run("config map in another namespace", func(t *testing.T) {
		got := lintWith(t, func(objs []kobj.Object) []kobj.Object {
			cm := find(t, objs, kobj.KindConfigMap, compile.DenyPolicyName)
			cm.Namespace = "apps"
			return objs
		})
		wantFinding(t, got, "config map is not runos/"+compile.DenyPolicyName)
	})
}

func TestLintScopeHoldsABundleToItsNamedNamespaces(t *testing.T) {
	objs := cleanSet()
	if got := compile.LintScope(objs, []string{"apps"}); len(got) != 0 {
		t.Fatalf("a bundle inside its namespaces has findings: %q", got)
	}
	got := compile.LintScope(objs, []string{"other"})
	wantFinding(t, got, "namespace is not managed by this bundle")
	wantFinding(t, got, "namespace apps is not managed by this bundle")
	if !slices.IsSorted(got) {
		t.Fatalf("not sorted: %q", got)
	}
}

func TestLintScopeLetsTheDenyListLiveOutsideTheManagedNamespaces(t *testing.T) {
	deny, err := compile.DenyObjects(testVersion, testAccount, nil, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := compile.LintScope(deny, nil); len(got) != 0 {
		t.Fatalf("the deny objects are outside the scope: %q", got)
	}
	// A config map that merely sits in the runos namespace under another name is not the list.
	stray := kobj.Object{Kind: kobj.KindConfigMap, Name: "other", Namespace: compile.DenyNamespace}
	wantFinding(t, compile.LintScope([]kobj.Object{stray}, nil), "namespace runos is not managed")
}
