package compile

// Immediate-cut deny list. RunOS writes a
// person's id into a ConfigMap in the runos namespace of each cluster. A
// ValidatingAdmissionPolicy refuses every write by that person at once:
// create, update, delete and connect (exec, attach, port-forward). Reads do
// not pass admission, so they stay possible until the token expires. Each
// entry carries its expiry, the longest Kubernetes token lifetime after the
// cut; the next compile after that drops it. CEL has no clock, so RunOS
// drops the entry, not the API server.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/runos-official/rolekeeper/internal/kobj"
)

// Deny is one deny-list entry.
type Deny struct {
	Person string    `json:"person"`
	Until  time.Time `json:"until"`
}

// Names of the deny-list objects. The list lives in the runos namespace,
// which no person binding reaches.
const (
	DenyPolicyName = "runos-deny-writes"
	DenyNamespace  = "runos"
)

// The deny canary. The applier keeps one of two reserved subjects
// on the list and turns it over now and then. After each pass it asks the
// API server, in a dry run as each canary, whether the listed one is
// refused and the unlisted one is not. A fixed canary would not do: a
// re-created policy can keep an old copy of its list (measured on kind v1.36.1),
// so a canary that never moves stays refused while new entries are not.
// The keys are not roid ids (SubjectIDFor hashes them), so no person can be
// a canary.
var DenyCanaries = [2]string{"runos-deny-canary-a", "runos-deny-canary-b"}

// CanaryUntil is the value of a canary entry: a valid RFC 3339 time that
// never passes. CEL has no clock, so the value only has to pass lint.
const CanaryUntil = "9999-12-31T23:59:59Z"

// IsDenyCanary reports whether a deny-list key is a canary.
func IsDenyCanary(key string) bool { return key == DenyCanaries[0] || key == DenyCanaries[1] }

// CanaryUser is the Kubernetes user name of a canary, as the policy sees it.
func CanaryUser(key string) string { return UserPrefix + key }

// IsKeptDenyObject names the deny policy and its binding. No RunOS code
// deletes them: a deleted and re-created ConfigMap-param policy stops
// seeing changes to its list until kube-apiserver restarts, so they
// are only ever updated in place.
//
// Every Delete of a RunOS Kubernetes client refuses them with
// ErrDenyPolicyKept.
func IsKeptDenyObject(kind, name string) bool {
	return (kind == kobj.KindVAP || kind == kobj.KindVAPBinding) && name == DenyPolicyName
}

// ErrDenyPolicyKept is the refusal of a delete of the deny policy or its
// binding.
var ErrDenyPolicyKept = errors.New("the deny policy and its binding are never deleted: a re-created policy does not see its list until kube-apiserver restarts")

// denyExpr refuses a person on the list. The ConfigMap key is the person id
// (ConfigMap keys cannot hold ":"), so the expression strips "runos:u:".
const (
	denyMatch = "request.userInfo.username.startsWith('" + UserPrefix + "')"
	denyExpr  = "!has(params.data) || !(request.userInfo.username.substring(8) in params.data)"
)

func generic(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m
}

// DenyPolicySpec is the spec of the deny ValidatingAdmissionPolicy. It
// applies only to RunOS person users and never blocks the platform's own
// controllers.
func DenyPolicySpec() map[string]any {
	if len(UserPrefix) != 8 {
		panic("denyExpr assumes an 8-byte user prefix")
	}
	return generic(map[string]any{
		"failurePolicy": "Fail",
		"paramKind":     map[string]any{"apiVersion": "v1", "kind": "ConfigMap"},
		"matchConstraints": map[string]any{"resourceRules": []any{map[string]any{
			"apiGroups": []string{"*"}, "apiVersions": []string{"*"}, "resources": []string{"*/*"},
			"operations": []string{"CREATE", "UPDATE", "DELETE", "CONNECT"},
		}}},
		"matchConditions": []any{map[string]any{"name": "runos-person", "expression": denyMatch}},
		"validations": []any{map[string]any{
			"expression": denyExpr,
			"message":    "runos: this person's writes are cut (deny list)",
			"reason":     "Forbidden",
		}},
	})
}

// DenyBindingSpec binds the policy to the list. A missing list allows:
// with Deny, the API server refuses every matched write by every user
// before matchConditions run, which stopped a whole kind cluster (node
// lease included) and kept the applier from writing the list back.
// Anyone who can delete the list can delete the binding too, and the
// applier writes the list again in its next pass.
func DenyBindingSpec() map[string]any {
	return generic(map[string]any{
		"policyName":        DenyPolicyName,
		"validationActions": []string{"Deny"},
		"paramRef": map[string]any{
			"name": DenyPolicyName, "namespace": DenyNamespace, "parameterNotFoundAction": "Allow",
		},
	})
}

// DenyObjects returns the policy, the list and the binding, in apply order.
// An entry whose expiry has passed is left out. Two entries for one person
// keep the later expiry.
func DenyObjects(pv, account string, deny []Deny, now time.Time) ([]kobj.Object, error) {
	data := map[string]string{}
	until := map[string]time.Time{}
	for _, d := range deny {
		if IsDenyCanary(d.Person) {
			return nil, &Error{Code: "policy.invalid", Reason: fmt.Sprintf("deny-list person id %q is a reserved canary", d.Person)}
		}
		if !ValidSubjectID(d.Person) {
			return nil, &Error{Code: "policy.invalid", Reason: fmt.Sprintf("deny-list person id %q cannot be a Kubernetes subject", d.Person)}
		}
		if !now.Before(d.Until) {
			continue
		}
		if d.Until.After(until[d.Person]) {
			until[d.Person] = d.Until
			data[d.Person] = d.Until.UTC().Format(time.RFC3339)
		}
	}
	return []kobj.Object{
		{Kind: kobj.KindVAP, Name: DenyPolicyName, Labels: labels(pv, account), Spec: DenyPolicySpec()},
		{Kind: kobj.KindConfigMap, Name: DenyPolicyName, Namespace: DenyNamespace, Labels: labels(pv, account), Data: data},
		{Kind: kobj.KindVAPBinding, Name: DenyPolicyName, Labels: labels(pv, account), Spec: DenyBindingSpec()},
	}, nil
}

// lintDeny checks one deny-list object against the compiled shape.
func lintDeny(o kobj.Object) []string {
	var v []string
	switch o.Kind {
	case kobj.KindVAP:
		if o.Name != DenyPolicyName || o.Namespace != "" {
			v = append(v, "admission policy is not "+DenyPolicyName)
		}
		if !reflect.DeepEqual(generic(o.Spec), DenyPolicySpec()) {
			v = append(v, "admission policy spec differs from the compiled deny policy")
		}
	case kobj.KindVAPBinding:
		if o.Name != DenyPolicyName || o.Namespace != "" {
			v = append(v, "admission binding is not "+DenyPolicyName)
		}
		if !reflect.DeepEqual(generic(o.Spec), DenyBindingSpec()) {
			v = append(v, "admission binding spec differs from the compiled deny binding")
		}
	case kobj.KindConfigMap:
		if o.Name != DenyPolicyName || o.Namespace != DenyNamespace {
			v = append(v, "config map is not "+DenyNamespace+"/"+DenyPolicyName)
		}
		for _, k := range slices.Sorted(maps.Keys(o.Data)) {
			if !ValidSubjectID(k) {
				v = append(v, fmt.Sprintf("deny-list key %q is not a person id", k))
			}
			if _, err := time.Parse(time.RFC3339, o.Data[k]); err != nil {
				v = append(v, fmt.Sprintf("deny-list entry %s has no RFC 3339 expiry", k))
			}
		}
	}
	return v
}

// InstallPolicyVersion labels the deny objects the installer writes. The
// applier's first pass relabels them with the bundle's policy version.
const InstallPolicyVersion = "install"

// DenyInstallList is the deny policy, an empty list and the binding as one
// v1 List for the installer, in that order: the list goes first, so the
// binding never stands without it. The installer creates these because
// Kubernetes lets only a writer who may get every ConfigMap create a policy
// whose paramKind is ConfigMap; the applier then keeps them.
func DenyInstallList(account string) []byte {
	objs, _ := DenyObjects(InstallPolicyVersion, account, nil, time.Time{})
	order := []kobj.Object{objs[1], objs[0], objs[2]}
	var buf bytes.Buffer
	_ = json.Indent(&buf, kobj.List(order), "", "  ")
	buf.WriteByte('\n')
	return buf.Bytes()
}
