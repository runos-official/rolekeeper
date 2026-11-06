package compile

// Break-glass platform objects. These are
// install-time platform objects, outside the person projection: they carry
// no runos.com/roid-managed label, so the reconciler never removes them, and Lint
// does not judge them.
//
// The emergency certificate and the sealed custody release both name group
// runos:breakglass. That group was formerly bound to cluster-admin. It is
// now bound to a defined break-glass role:
//
//   - Read (get, list, watch) on every built-in resource except Secrets.
//     RBAC cannot subtract, so the role lists resources and never uses a
//     wildcard. Secrets are read nowhere, not even in managed namespaces:
//     restoring access never needs a Secret value. A holder who needs one
//     can bind runos:secrets-read in a managed namespace, which leaves a
//     second, separate audit record.
//   - RBAC writes on roles, rolebindings, clusterroles and
//     clusterrolebindings, plus bind on the five fixed RunOS roles only, so
//     a person's grants can be restored. No escalate, no impersonate.
//   - No admission-policy write at all. Admission
//     never runs on admission-policy objects, so no guard can bound them:
//     a policy that refuses every write would also refuse the controllers
//     and the reconciler, and break-glass could not remove it. The deny
//     list is edited through its ConfigMap only.
//   - Read and delete on webhook configurations, to remove a broken webhook
//     that blocks the API. Never create or update: a mutating webhook can
//     rewrite any object, including the reconciler's own bindings.
//   - get, update and patch on the deny-list ConfigMap, through a
//     RoleBinding in its namespace.
//
// The guard ValidatingAdmissionPolicy runos-breakglass-guard matches only
// requests from group runos:breakglass. It refuses:
//
//   - RBAC writes in a protected namespace, and in any namespace that RunOS
//     does not manage (label runos.com/roid-access=true), because the managed
//     set is the only place a RunOS role may reach;
//   - every ClusterRoleBinding operation (a cluster-wide grant reaches
//     kube-system, and a delete removes the platform's own bindings);
//   - any ClusterRole write that is not a new runos: ClusterRole, so the five
//     fixed roles and the break-glass roles can be neither changed nor
//     deleted;
//   - a Role or RoleBinding without the stamp annotation runos.com/breakglass
//     (an RFC 3339 expiry). The reconciler removes a stamped object once it
//     passes;
//   - a RoleBinding whose roleRef is not one of the five fixed roles, or
//     whose subjects are not Groups that name that same role in the claim
//     form: runos:g:<group>:<role>, runos:u:<person>:<role> or
//     runos:cw:<role>. A bare User subject is refused,
//     and a Role (a custom permission set) cannot be bound at all.

import (
	"slices"
	"strings"
	"time"

	"github.com/runos-official/rolekeeper/kobj"
)

const (
	// BreakGlassGroup is the group in every break-glass certificate.
	BreakGlassGroup = "runos:breakglass"
	// RoleBreakGlass is the break-glass ClusterRole and its binding name.
	RoleBreakGlass = "runos:breakglass"
	// RoleBreakGlassDenyList grants the deny-list ConfigMap edit, bound
	// only in DenyListNamespace.
	RoleBreakGlassDenyList = "runos:breakglass-deny-list"
	// BreakGlassGuardName names the guard policy and its binding.
	BreakGlassGuardName = "runos-breakglass-guard"
	// LabelPlatform marks a platform object outside the person projection.
	LabelPlatform = "runos.com/platform"
)

// Deny-list object names. deny.go owns the objects; the
// break-glass role names them so it can edit them.
const (
	DenyListNamespace  = DenyNamespace
	DenyListConfigMap  = DenyPolicyName
	DenyListPolicyName = DenyPolicyName
	DenyListBinding    = DenyPolicyName
)

// breakGlassReads lists every built-in resource break-glass reads, per API
// group, as served by Kubernetes 1.33 to 1.36. Secrets are absent on
// purpose. Custom resources are not covered.
var breakGlassReads = []struct {
	Group     string
	Resources []string
}{
	{"", []string{"pods", "pods/log", "pods/status", "services", "services/status", "endpoints", "configmaps", "events",
		"persistentvolumeclaims", "persistentvolumeclaims/status", "persistentvolumes", "replicationcontrollers",
		"namespaces", "namespaces/status", "nodes", "nodes/status", "serviceaccounts", "resourcequotas", "limitranges",
		"podtemplates", "componentstatuses"}},
	{"apps", []string{"deployments", "deployments/status", "replicasets", "statefulsets", "daemonsets", "controllerrevisions"}},
	{"batch", []string{"jobs", "cronjobs"}},
	{"autoscaling", []string{"horizontalpodautoscalers"}},
	{"policy", []string{"poddisruptionbudgets"}},
	{"networking.k8s.io", []string{"ingresses", "ingressclasses", "networkpolicies", "ipaddresses", "servicecidrs"}},
	{"discovery.k8s.io", []string{"endpointslices"}},
	{"events.k8s.io", []string{"events"}},
	{"rbac.authorization.k8s.io", []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}},
	{"admissionregistration.k8s.io", []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings",
		"validatingwebhookconfigurations", "mutatingwebhookconfigurations", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings"}},
	{"apiextensions.k8s.io", []string{"customresourcedefinitions"}},
	{"apiregistration.k8s.io", []string{"apiservices"}},
	{"storage.k8s.io", []string{"storageclasses", "csidrivers", "csinodes", "csistoragecapacities", "volumeattachments", "volumeattributesclasses"}},
	{"scheduling.k8s.io", []string{"priorityclasses"}},
	{"node.k8s.io", []string{"runtimeclasses"}},
	{"coordination.k8s.io", []string{"leases"}},
	{"certificates.k8s.io", []string{"certificatesigningrequests"}},
	{"flowcontrol.apiserver.k8s.io", []string{"flowschemas", "prioritylevelconfigurations"}},
	{"resource.k8s.io", []string{"deviceclasses", "resourceclaims", "resourceclaimtemplates", "resourceslices"}},
}

// BreakGlassRules returns the rules of the break-glass ClusterRole.
func BreakGlassRules() []kobj.Rule {
	var rs []kobj.Rule
	for _, g := range breakGlassReads {
		rs = append(rs, kobj.Rule{APIGroups: core(g.Group), Resources: slices.Clone(g.Resources), Verbs: core("get", "list", "watch")})
	}
	rbac := "rbac.authorization.k8s.io"
	adm := "admissionregistration.k8s.io"
	rs = append(rs,
		kobj.Rule{APIGroups: core(rbac), Resources: core("roles", "rolebindings", "clusterroles", "clusterrolebindings"),
			Verbs: core("create", "update", "patch", "delete")},
		kobj.Rule{APIGroups: core(rbac), Resources: core("clusterroles"), Verbs: core("bind"), ResourceNames: slices.Clone(fixedRoleNames)},
		kobj.Rule{APIGroups: core(adm), Resources: core("validatingwebhookconfigurations", "mutatingwebhookconfigurations"), Verbs: core("delete")},
	)
	return rs
}

// BreakGlassObjects returns the break-glass RBAC objects: the ClusterRole
// and its ClusterRoleBinding, and the deny-list ConfigMap grant. The guard
// policy is separate (BreakGlassGuard), because kobj does not model it.
func BreakGlassObjects(version string) []kobj.Object {
	lab := func() map[string]string {
		return map[string]string{LabelPlatform: "breakglass", kobj.LabelPolicyVersion: version}
	}
	group := []kobj.Subject{{Kind: "Group", Name: BreakGlassGroup, APIGroup: "rbac.authorization.k8s.io"}}
	return []kobj.Object{
		{Kind: kobj.KindClusterRole, Name: RoleBreakGlass, Labels: lab(), Rules: BreakGlassRules()},
		{Kind: kobj.KindClusterRoleBinding, Name: RoleBreakGlass, Labels: lab(), Subjects: group,
			RoleRef: &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: RoleBreakGlass}},
		{Kind: kobj.KindClusterRole, Name: RoleBreakGlassDenyList, Labels: lab(), Rules: []kobj.Rule{
			{APIGroups: core(""), Resources: core("configmaps"), Verbs: core("get", "update", "patch"), ResourceNames: []string{DenyListConfigMap}},
		}},
		{Kind: kobj.KindRoleBinding, Name: RoleBreakGlassDenyList, Namespace: DenyListNamespace, Labels: lab(), Subjects: group,
			RoleRef: &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: RoleBreakGlassDenyList}},
	}
}

// BreakGlassStamp is the annotation the guard requires on every Role and
// RoleBinding that break-glass writes. Its value is an RFC 3339 expiry. The
// reconciler removes a stamped object once the expiry passes, or once it has
// stood longer than BreakGlassStampMax since the reconciler first saw it.
const BreakGlassStamp = "runos.com/breakglass"

// BreakGlassStampMax is the longest a stamped object stands: the emergency
// certificate lives 16 minutes, and one reconcile interval of grace follows.
const BreakGlassStampMax = 20 * time.Minute

// platformClusterRoles are the ClusterRoles break-glass can neither change
// nor delete: the five fixed roles and its own two.
func platformClusterRoles() []string {
	return append(slices.Clone(fixedRoleNames), RoleBreakGlass, RoleBreakGlassDenyList)
}

// PlatformClusterRolesForTest returns the ClusterRoles that break-glass can
// neither change nor delete.
func PlatformClusterRolesForTest() []string { return platformClusterRoles() }

func celList(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = "'" + s + "'"
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// BreakGlassGuard returns the guard ValidatingAdmissionPolicy and its
// binding, as one v1 List manifest.
func BreakGlassGuard() map[string]any {
	protected := ProtectedNamespaceCEL("request.namespace")
	name := "(request.operation == 'DELETE' ? oldObject.metadata.name : object.metadata.name)"
	managedNS := "(has(namespaceObject.metadata.labels) && '" + kobj.LabelAccess + "' in namespaceObject.metadata.labels && " +
		"namespaceObject.metadata.labels['" + kobj.LabelAccess + "'] == 'true')"
	writes := "request.operation != 'DELETE'"
	// A subject is a Group that names the role of the roleRef, in one of
	// the three claim forms. The id has no ':' so the role is the last part.
	subjectOK := "s.kind == 'Group' && (s.name == 'runos:cw:' + object.roleRef.name.substring(6) || " +
		"s.name.matches('^runos:[gu]:[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?:' + object.roleRef.name.substring(6) + '$'))"
	policy := map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicy",
		"metadata":   map[string]any{"name": BreakGlassGuardName, "labels": map[string]string{LabelPlatform: "breakglass"}},
		"spec": map[string]any{
			"failurePolicy": "Fail",
			"matchConstraints": map[string]any{"resourceRules": []any{map[string]any{
				"apiGroups": []string{"rbac.authorization.k8s.io"}, "apiVersions": []string{"*"},
				"operations": []string{"CREATE", "UPDATE", "DELETE"},
				"resources":  []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"},
			}}},
			"matchConditions": []any{map[string]any{
				"name": "breakglass", "expression": "request.userInfo.groups.exists(g, g == '" + BreakGlassGroup + "')",
			}},
			"validations": []any{
				map[string]any{"expression": "!has(request.namespace) || request.namespace == '' || !" + protected,
					"message": "runos: break-glass cannot change RBAC in a protected namespace"},
				map[string]any{"expression": "!has(request.namespace) || request.namespace == '' || " + managedNS,
					"message": "runos: break-glass changes RBAC only in a namespace that RunOS manages"},
				map[string]any{"expression": "request.kind.kind != 'ClusterRoleBinding'",
					"message": "runos: break-glass cannot create, change or delete a ClusterRoleBinding"},
				map[string]any{"expression": "request.kind.kind != 'ClusterRole' || (request.operation == 'CREATE' && " + name + ".startsWith('runos:') && !(" + name + " in " + celList(platformClusterRoles()) + "))",
					"message": "runos: break-glass cannot change or delete a platform ClusterRole, and creates only runos: ones"},
				map[string]any{"expression": "!(request.kind.kind in ['Role', 'RoleBinding']) || !(" + writes + ") || (has(object.metadata.annotations) && '" + BreakGlassStamp + "' in object.metadata.annotations)",
					"message": "runos: a break-glass Role or RoleBinding carries the annotation " + BreakGlassStamp + " (an RFC 3339 expiry)"},
				map[string]any{"expression": "request.kind.kind != 'RoleBinding' || !(" + writes + ") || (object.roleRef.kind == 'ClusterRole' && object.roleRef.name in " + celList(fixedRoleNames) + ")",
					"message": "runos: break-glass binds only the five fixed RunOS ClusterRoles"},
				map[string]any{"expression": "request.kind.kind != 'RoleBinding' || !(" + writes + ") || (has(object.subjects) && size(object.subjects) > 0 && object.subjects.all(s, " + subjectOK + "))",
					"message": "runos: a break-glass binding names only Groups runos:g:<group>:<role>, runos:u:<person>:<role> or runos:cw:<role>, for the role it binds"},
				map[string]any{"expression": "request.kind.kind != 'Role' || !(" + writes + ") || false",
					"message": "runos: break-glass creates no Role: a custom permission set cannot be bound"},
			},
		},
	}
	binding := map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": BreakGlassGuardName, "labels": map[string]string{LabelPlatform: "breakglass"}},
		"spec":       map[string]any{"policyName": BreakGlassGuardName, "validationActions": []string{"Deny"}},
	}
	return map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{policy, binding}}
}
