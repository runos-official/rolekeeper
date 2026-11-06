// Package compile holds the Kubernetes objects of RunOS access: the five
// fixed RunOS ClusterRoles, RoleBindings in each managed namespace, Pod
// Security labels on every managed namespace, and the immediate-cut deny
// list. Subjects are runos: groups: runos:g:<group>:<role> for a namespace
// group grant and runos:cw:<role> for every cluster-wide grant. Every group
// subject names its role, so a token's group claims reach only the roles it
// was issued for. Only a direct namespace grant binds a person. It never
// emits a ClusterRoleBinding. Every object carries the policy version. Lint
// checks a set of objects against the escalation rules. The projection from
// the policy model to these objects is not part of this package in
// rolekeeper.
package compile

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/runos-official/rolekeeper/kobj"
)

// Subject name prefixes. A token carries the person's runos:
// groups in its groups claim. A group claim names the group
// and the role: runos:g:<group>:<role>.
const (
	UserPrefix  = "runos:u:"
	GroupPrefix = "runos:g:"
)

// ClusterWidePrefix names the RunOS groups that carry a cluster-wide right
// for one fixed role, for example runos:cw:view.
const ClusterWidePrefix = "runos:cw:"

// ClusterWideGroup is the RunOS group that holds role in every managed
// namespace of a cluster.
func ClusterWideGroup(role string) string {
	return ClusterWidePrefix + strings.TrimPrefix(role, "runos:")
}

// Claim validation rules of the API server's AuthenticationConfiguration
// (the rules are the backstop when the issuer is wrong). The rendered
// configuration carries these exact texts.
const (
	// UsernameRule holds the token subject to the person-id shape that
	// ValidSubjectID enforces. The deny list looks
	// the username up after stripping runos:u:, so no other shape may pass.
	UsernameRule = `claims.sub.matches('^runos:u:[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$')`

	// LifetimeRule caps every token at 900 s, and every token that carries a
	// claim other than :view at 300 s.
	LifetimeRule = `claims.exp - claims.iat <= 900 && (claims.exp - claims.iat <= 300 || ` +
		`!has(claims.groups) || dyn(claims.groups).all(g, g.endsWith(':view')))`

	// ClaimGroupsRule is the claim validation rule for the groups claim.
	// Every group must be runos:g:<group>:<role> or runos:cw:<role>, with
	// role one of the five fixed roles, or the token's own person claim
	// runos:u:<person>:<role>: the part before the role must equal the
	// token subject.
	ClaimGroupsRule = `!has(claims.groups) || dyn(claims.groups).all(g, ` +
		`g.matches('^runos:g:[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?:(view|edit|exec|ns-admin|secrets-read)$') || ` +
		`(g.startsWith(claims.sub + ':') && g.substring(size(claims.sub) + 1).matches('^(view|edit|exec|ns-admin|secrets-read)$')) || ` +
		`g.matches('^runos:cw:(view|edit|exec|ns-admin|secrets-read)$'))`
)

// The other rules of the AuthenticationConfiguration. Together with the
// three above they are the one list the rendered configuration carries.
const (
	// PurposeRule accepts only tokens signed for the kubernetes-issuer purpose.
	PurposeRule = `claims.purpose == 'kubernetes-issuer'`
	// ClassRule accepts only person tokens.
	ClassRule = `claims.cls == 'person'`
	// JTIRule needs a token id: the cut and the audit key on it.
	JTIRule = `has(claims.jti) && claims.jti != ''`
	// NoSystemUserRule and NoSystemGroupRule keep a RunOS token out of the
	// system: names of Kubernetes.
	NoSystemUserRule  = `!user.username.startsWith('system:')`
	NoSystemGroupRule = `user.groups.all(g, !g.startsWith('system:'))`
)

// Rule is one CEL rule of the AuthenticationConfiguration with the message
// the API server shows when it refuses.
type Rule struct{ Expression, Message string }

// ClaimValidationRules are the claimValidationRules, in order.
func ClaimValidationRules() []Rule {
	return []Rule{
		{PurposeRule, "runos: token purpose must be kubernetes-issuer"},
		{ClassRule, "runos: token class must be person"},
		{JTIRule, "runos: jti required"},
		{LifetimeRule, "runos: lifetime above 900s, or above 300s with a role other than view"},
		{UsernameRule, "runos: username is not runos:u:<person id>"},
		{ClaimGroupsRule, "runos: groups outside runos:g:<group>:<role>, runos:cw:<role> and the token own runos:u:<person>:<role>"},
	}
}

// UserValidationRules are the userValidationRules, in order.
func UserValidationRules() []Rule {
	return []Rule{
		{NoSystemUserRule, "runos: system: username refused"},
		{NoSystemGroupRule, "runos: system: group refused"},
	}
}

// ShortRole is a fixed role name without its runos: prefix, for example
// "edit" for runos:edit.
func ShortRole(role string) string { return strings.TrimPrefix(role, "runos:") }

// GroupSubject is the binding subject and token claim for one group holding
// one fixed role: runos:g:<group>:<role>. A group id never
// holds a ":", so the last ":" splits the group from the role.
func GroupSubject(group, role string) string {
	return GroupPrefix + group + ":" + ShortRole(role)
}

// PersonRoleSubject is the binding subject and token claim for one person
// holding one fixed role directly: runos:u:<person>:<role>.
// It is a Kubernetes Group, so a token reaches only the roles it was issued
// for. The bare runos:u:<person> stays the token user name, for audit and
// the deny list only.
func PersonRoleSubject(person, role string) string {
	return UserPrefix + person + ":" + ShortRole(role)
}

// SplitPersonRoleSubject returns the person and the short role of a
// runos:u:<person>:<role> subject.
func SplitPersonRoleSubject(subject string) (person, short string, ok bool) {
	rest, ok := strings.CutPrefix(subject, UserPrefix)
	if !ok {
		return "", "", false
	}
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// SplitGroupSubject returns the group and the short role of a
// runos:g:<group>:<role> subject.
func SplitGroupSubject(subject string) (group, short string, ok bool) {
	rest, ok := strings.CutPrefix(subject, GroupPrefix)
	if !ok {
		return "", "", false
	}
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// subjectID is the shape of a person or group id that may reach a subject
// name and a binding name: lower-case letters, digits, "-" and ".", starting
// and ending with a letter or digit. A ":" would change the username shape
// and a "/" would break the apply of the whole cluster.
var subjectID = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)

// ValidSubjectID reports whether id may be projected into Kubernetes.
func ValidSubjectID(id string) bool { return subjectID.MatchString(id) }

// Cluster is the RunOS inventory of one cluster: its account, id and the
// namespaces RunOS manages there. System namespaces are never managed.
type Cluster struct {
	Account    string
	ID         string
	Namespaces []string
}

// Entry records why one subject holds one role in one place. The issuer
// uses entries to decide whether a person may get a token for the cluster,
// which runos: groups the token carries, and how long it lives.
type Entry struct {
	// Subject is the binding subject: runos:u:<person>:<role>,
	// runos:g:<group>:<role> or runos:cw:<role>. Kind is "Group" for all
	// three.
	Subject string
	Kind    string
	GrantID string
	Action  string
	Role    string
	// Namespace is the managed namespace of a namespace grant; "" means
	// every managed namespace (a cluster-wide grant).
	Namespace string
	ExpiresAt time.Time // zero when the grant has no end
	// Person is the person of a direct grant. Via is the group id of a
	// group grant. Exactly one is set.
	Person string
	Via    string
}

// Output is one compiled projection.
type Output struct {
	PolicyVersion string
	Objects       []kobj.Object
	Entries       []Entry
	// Skipped lists grants that do not project into this cluster, with why.
	Skipped []string
	// DenyOnly is true when the projection was refused with an error and
	// Objects holds only the deny-list objects.
	DenyOnly bool
}

// Error is a compile refusal in the response-contract shape.
type Error struct {
	Code   string // policy.unenforceable or policy.invalid
	Grant  string
	Reason string
	// Conditions names the grant conditions that RBAC cannot express, in a
	// fixed order, when that is why the grant is unenforceable.
	Conditions []string
	// Namespace is the system namespace of a grant that sits in one.
	Namespace string
}

func (e *Error) Error() string { return e.Code + " grant=" + e.Grant + ": " + e.Reason }

// Version renders a policy snapshot version as a label value.
func Version(v uint64) string { return "pv-" + itoa(v) }

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// SystemNamespaces are never managed and never receive a person binding.
// With every name that starts with ProtectedPrefix, they are the protected
// namespaces. IsSystemNamespace and ProtectedNamespaceCEL are the only two
// renderings of that rule; every other check calls one of them.
//
// ApplierNamespace is among them: its service account writes
// cluster-wide RBAC, so a person who could run a pod there could too.
var SystemNamespaces = []string{"kube-system", "kube-public", "kube-node-lease", "default", "runos", "local-path-storage", ApplierNamespace}

// ApplierNamespace is the namespace of the in-cluster applier
// (k8s/deploy/roid-k8s-applier.yaml). It holds the version floor and the
// canary writes.
const ApplierNamespace = "roid-k8s-applier"

// ProtectedPrefix marks a namespace as protected by name alone.
const ProtectedPrefix = "kube-"

// IsSystemNamespace reports whether ns is reserved for the platform (a
// protected namespace).
func IsSystemNamespace(ns string) bool {
	return slices.Contains(SystemNamespaces, ns) || strings.HasPrefix(ns, ProtectedPrefix)
}

// ProtectedNamespaceCEL is IsSystemNamespace as a CEL expression over the
// namespace expression ns, for admission policies.
func ProtectedNamespaceCEL(ns string) string {
	q := make([]string, len(SystemNamespaces))
	for i, x := range SystemNamespaces {
		q[i] = "'" + x + "'"
	}
	return "(" + ns + " in [" + strings.Join(q, ", ") + "] || " + ns + ".startsWith('" + ProtectedPrefix + "'))"
}

// Pod Security labels on every managed namespace.
var PSALabels = map[string]string{
	"pod-security.kubernetes.io/enforce":         "baseline",
	"pod-security.kubernetes.io/enforce-version": "latest",
	"pod-security.kubernetes.io/warn":            "restricted",
	"pod-security.kubernetes.io/audit":           "restricted",
}

// BindingName is the deterministic binding name for one role and subject,
// for example runos:view:u:viewer-a, runos:edit:g:grp-ops (subject
// runos:g:grp-ops:edit) or runos:view:cw.
func BindingName(role, subject string) string {
	short := ShortRole(role)
	if g, _, ok := SplitGroupSubject(subject); ok {
		return "runos:" + short + ":g:" + g
	}
	switch {
	case strings.HasPrefix(subject, ClusterWidePrefix):
		return "runos:" + short + ":cw"
	case strings.HasPrefix(subject, UserPrefix):
		if p, _, ok := SplitPersonRoleSubject(subject); ok {
			return "runos:" + short + ":u:" + p
		}
		return "runos:" + short + ":u:" + strings.TrimPrefix(subject, UserPrefix)
	}
	return "runos:" + short + ":" + subject
}

var (
	streamResources = []string{"pods/exec", "pods/attach", "pods/portforward", "pods/ephemeralcontainers"}
	forbiddenVerbs  = []string{"impersonate", "bind", "escalate", "approve", "sign"}
	forbiddenRes    = []string{"nodes/proxy", "pods/proxy", "services/proxy", "serviceaccounts/token", "serviceaccounts", "certificatesigningrequests", "certificatesigningrequests/approval", "tokenreviews", "subjectaccessreviews", "clusterroles", "clusterrolebindings", "nodes", "namespaces", "mutatingwebhookconfigurations", "validatingwebhookconfigurations"}
	rbacResources   = []string{"roles", "rolebindings"}
	fixedRoleNames  = []string{RoleView, RoleEdit, RoleNSAdmin, RoleSecretsRead, RoleExec}
	readVerbs       = []string{"get", "list", "watch"}
)

// IsFixedRole reports whether name is one of the five fixed RunOS roles.
func IsFixedRole(name string) bool { return slices.Contains(fixedRoleNames, name) }

// Lint returns every escalation-rule violation in a compiled object set.
// It is the gate in front of every apply: a compiled set with a violation
// is never applied.
func Lint(objs []kobj.Object) []string {
	var v []string
	bad := func(o kobj.Object, f string, a ...any) { v = append(v, o.Key()+": "+fmt.Sprintf(f, a...)) }
	for _, o := range objs {
		// A namespace carries the opt-in label; every other object carries the
		// marker for objects roid creates.
		marker := kobj.LabelManaged
		if o.Kind == kobj.KindNamespace {
			marker = kobj.LabelAccess
		}
		if o.Labels[marker] != "true" || o.Labels[kobj.LabelPolicyVersion] == "" {
			bad(o, "label: missing %s or %s", marker, kobj.LabelPolicyVersion)
		}
		for k := range o.Labels {
			if strings.Contains(k, "aggregate-to") {
				bad(o, "aggregation label %s", k)
			}
		}
		switch o.Kind {
		case kobj.KindNamespace:
			if IsSystemNamespace(o.Name) {
				bad(o, "system namespace is managed")
			}
			if o.Labels["pod-security.kubernetes.io/enforce"] != "baseline" && o.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
				bad(o, "pod security enforce=%q, want baseline or restricted", o.Labels["pod-security.kubernetes.io/enforce"])
			}
		case kobj.KindClusterRole:
			if !slices.Contains(fixedRoleNames, o.Name) {
				bad(o, "not a fixed RunOS role")
			}
			if o.Aggregation {
				bad(o, "aggregationRule")
			}
			for _, r := range o.Rules {
				for _, f := range [][]string{r.APIGroups, r.Resources, r.Verbs} {
					if slices.Contains(f, "*") {
						bad(o, "wildcard in %+v", r)
					}
				}
				for _, verb := range r.Verbs {
					if slices.Contains(forbiddenVerbs, verb) {
						bad(o, "forbidden verb %s", verb)
					}
				}
				for _, res := range r.Resources {
					if slices.Contains(streamResources, res) && o.Name != RoleExec {
						bad(o, "stream subresource %s outside %s", res, RoleExec)
					}
					if slices.Contains(forbiddenRes, res) {
						bad(o, "forbidden resource %s", res)
					}
					if slices.Contains(rbacResources, res) && o.Name != RoleNSAdmin {
						bad(o, "rbac resource %s outside %s", res, RoleNSAdmin)
					}
					if res == "secrets" && o.Name != RoleSecretsRead && slices.ContainsFunc(r.Verbs, func(x string) bool { return slices.Contains(readVerbs, x) }) {
						bad(o, "secrets read outside %s", RoleSecretsRead)
					}
				}
			}
		case kobj.KindRoleBinding, kobj.KindClusterRoleBinding:
			if o.RoleRef == nil || o.RoleRef.Kind != kobj.KindClusterRole || !slices.Contains(fixedRoleNames, o.RoleRef.Name) {
				bad(o, "roleRef %+v is not a fixed RunOS ClusterRole", o.RoleRef)
			}
			if o.Kind == kobj.KindClusterRoleBinding {
				// Every grant expands into managed namespaces.
				bad(o, "ClusterRoleBinding is never compiled; cluster-wide grants expand into managed namespaces")
			}
			if o.Kind == kobj.KindRoleBinding && IsSystemNamespace(o.Namespace) {
				bad(o, "binding in system namespace %s", o.Namespace)
			}
			for _, s := range o.Subjects {
				if why := badSubject(s, o.RoleRef); why != "" {
					bad(o, "subject %s %s: %s", s.Kind, s.Name, why)
				}
			}
		case kobj.KindVAP, kobj.KindVAPBinding, kobj.KindConfigMap:
			for _, x := range lintDeny(o) {
				bad(o, "%s", x)
			}
		default:
			bad(o, "kind %s is not compiled by RunOS", o.Kind)
		}
	}
	sort.Strings(v)
	return v
}

// LintScope returns every object that lies outside the managed
// namespaces: a Namespace or a namespaced object in a namespace that
// managed does not hold. The deny list in DenyNamespace is the one
// namespaced object outside them. The applier is the last check when the
// issuer is wrong, so it holds a bundle to the namespaces the bundle
// names.
func LintScope(objs []kobj.Object, managed []string) []string {
	var v []string
	for _, o := range objs {
		switch {
		case o.Kind == kobj.KindNamespace:
			if !slices.Contains(managed, o.Name) {
				v = append(v, o.Key()+": namespace is not managed by this bundle")
			}
		case o.Kind == kobj.KindConfigMap && o.Name == DenyPolicyName && o.Namespace == DenyNamespace:
		case o.Namespace != "" && !slices.Contains(managed, o.Namespace):
			v = append(v, o.Key()+": namespace "+o.Namespace+" is not managed by this bundle")
		}
	}
	sort.Strings(v)
	return v
}

// badSubject says why a binding subject is not one RunOS compiles, or "".
// Allowed: the Groups runos:u:<person>:<role>,
// runos:g:<group>:<role> and runos:cw:<role>, each bound to its own fixed
// role only. A User subject is never allowed.
func badSubject(s kobj.Subject, ref *kobj.RoleRef) string {
	switch {
	case s.Kind == "Group" && strings.HasPrefix(s.Name, UserPrefix):
		p, short, ok := SplitPersonRoleSubject(s.Name)
		if !ok || !ValidSubjectID(p) {
			return "person id is not a plain name, or the subject names no role"
		}
		if ref == nil || !slices.Contains(fixedRoleNames, ref.Name) || short != ShortRole(ref.Name) {
			return "a person subject binds only the fixed role it names"
		}
	case s.Kind == "Group" && strings.HasPrefix(s.Name, GroupPrefix):
		g, short, ok := SplitGroupSubject(s.Name)
		if !ok || !ValidSubjectID(g) {
			return "group id is not a plain name, or the subject names no role"
		}
		if ref == nil || !slices.Contains(fixedRoleNames, ref.Name) || short != ShortRole(ref.Name) {
			return "a group subject binds only the fixed role it names"
		}
	case s.Kind == "Group" && strings.HasPrefix(s.Name, ClusterWidePrefix):
		if ref == nil || s.Name != ClusterWideGroup(ref.Name) || !slices.Contains(fixedRoleNames, ref.Name) {
			return "a cluster-wide group binds only its own fixed role"
		}
	default:
		return "not a runos:u:<person>:<role>, runos:g:<group>:<role> or runos:cw: group"
	}
	return ""
}
