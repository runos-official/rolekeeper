package compile_test

import (
	"maps"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

const (
	testVersion = "pv-1"
	testAccount = "acct-a"
)

// managedNamespace is a namespace as the compiler labels it: the opt-in label,
// the policy version and the Pod Security labels.
func managedNamespace(name string) kobj.Object {
	labels := map[string]string{
		kobj.LabelAccess:        "true",
		kobj.LabelPolicyVersion: testVersion,
		kobj.LabelAccount:       testAccount,
	}
	maps.Copy(labels, compile.PSALabels)
	return kobj.Object{Kind: kobj.KindNamespace, Name: name, Labels: labels}
}

// roleBinding binds one fixed role to one Group subject in a namespace.
func roleBinding(ns, role, subject string) kobj.Object {
	return kobj.Object{
		Kind:      kobj.KindRoleBinding,
		Name:      compile.BindingName(role, subject),
		Namespace: ns,
		Labels:    compile.Labels(testVersion, testAccount),
		Subjects:  []kobj.Subject{{Kind: "Group", Name: subject, APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:   &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: role},
	}
}

// cleanSet is a compiled set that must pass Lint: the five roles, one managed
// namespace with a group binding and a person binding, and the deny objects.
func cleanSet() []kobj.Object {
	objs := compile.FixedRoles(testVersion, testAccount)
	objs = append(objs,
		managedNamespace("apps"),
		roleBinding("apps", compile.RoleView, compile.GroupSubject("ops", compile.RoleView)),
		roleBinding("apps", compile.RoleEdit, compile.PersonRoleSubject("alice", compile.RoleEdit)),
		roleBinding("apps", compile.RoleView, compile.ClusterWideGroup(compile.RoleView)),
	)
	deny, err := compile.DenyObjects(testVersion, testAccount, nil, fixedNow)
	if err != nil {
		panic(err)
	}
	return append(objs, deny...)
}
