package compile

import (
	"github.com/runos-official/rolekeeper/internal/kobj"
)

// The fixed RunOS ClusterRoles. RunOS never binds the built-in view, edit,
// admin or cluster-admin roles, because those aggregate.
const (
	RoleView        = "runos:view"
	RoleEdit        = "runos:edit"
	RoleNSAdmin     = "runos:ns-admin"
	RoleSecretsRead = "runos:secrets-read"
	RoleExec        = "runos:exec"
)

// Policy actions that project into Kubernetes. Each maps to one fixed role.
// Every action targets a namespace, so a grant at cluster or account scope
// covers each namespace below it.
const (
	ActRead    = "k8s.resources.read"
	ActWrite   = "k8s.resources.write"
	ActSecrets = "k8s.secrets.read"
	ActExec    = "k8s.pods.exec"
	ActRBAC    = "k8s.rbac.admin"
)

// ActionRoles maps each Kubernetes action to its fixed role, in a fixed
// order (the order in which bindings are emitted).
var ActionRoles = []struct{ Action, Role string }{
	{ActRead, RoleView},
	{ActWrite, RoleEdit},
	{ActSecrets, RoleSecretsRead},
	{ActExec, RoleExec},
	{ActRBAC, RoleNSAdmin},
}

func core(rs ...string) []string { return rs }

// FixedRoles returns the five RunOS ClusterRoles, labelled with the policy
// version. Stream subresources (exec, attach, port-forward) and ephemeral
// containers appear only in runos:exec (on 1.33 and 1.34 `get`
// on pods/exec alone allows exec).
func FixedRoles(version, account string) []kobj.Object {
	mk := func(name string, rules ...kobj.Rule) kobj.Object {
		return kobj.Object{Kind: kobj.KindClusterRole, Name: name, Labels: labels(version, account), Rules: rules}
	}
	ro := core("get", "list", "watch")
	rw := core("create", "update", "patch", "delete")
	return []kobj.Object{
		mk(RoleView,
			kobj.Rule{APIGroups: core(""), Resources: core("pods", "pods/log", "pods/status", "services", "endpoints", "configmaps", "events", "persistentvolumeclaims", "replicationcontrollers"), Verbs: ro},
			kobj.Rule{APIGroups: core("apps"), Resources: core("deployments", "replicasets", "statefulsets", "daemonsets"), Verbs: ro},
			kobj.Rule{APIGroups: core("batch"), Resources: core("jobs", "cronjobs"), Verbs: ro},
			kobj.Rule{APIGroups: core("networking.k8s.io"), Resources: core("ingresses", "networkpolicies"), Verbs: ro},
		),
		mk(RoleEdit,
			kobj.Rule{APIGroups: core(""), Resources: core("pods", "services", "configmaps", "persistentvolumeclaims", "secrets"), Verbs: rw},
			kobj.Rule{APIGroups: core("apps"), Resources: core("deployments", "replicasets", "statefulsets", "daemonsets", "deployments/scale", "statefulsets/scale"), Verbs: rw},
			kobj.Rule{APIGroups: core("batch"), Resources: core("jobs", "cronjobs"), Verbs: rw},
		),
		mk(RoleSecretsRead,
			kobj.Rule{APIGroups: core(""), Resources: core("secrets"), Verbs: ro},
		),
		mk(RoleExec,
			kobj.Rule{APIGroups: core(""), Resources: core("pods/exec", "pods/attach", "pods/portforward"), Verbs: core("get", "create")},
			kobj.Rule{APIGroups: core(""), Resources: core("pods/ephemeralcontainers"), Verbs: core("patch", "update")},
		),
		// Ns-admin reads and deletes
		// roles and rolebindings. It holds no create, update or patch: only
		// RunOS creates bindings, from grants (R6). A holder who could write
		// bindings could bind any role it holds to any subject, and the
		// binding would outlive the grant.
		mk(RoleNSAdmin,
			kobj.Rule{APIGroups: core("rbac.authorization.k8s.io"), Resources: core("roles", "rolebindings"), Verbs: core("get", "list", "watch", "delete")},
		),
	}
}

func labels(version, account string) map[string]string {
	return map[string]string{kobj.LabelManaged: "true", kobj.LabelPolicyVersion: version, kobj.LabelAccount: account}
}
