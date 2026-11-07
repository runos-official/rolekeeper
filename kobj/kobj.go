// Package kobj is the small Kubernetes object model that the projection
// compiler emits and the reconciler compares. It covers only the kinds the
// compiler owns: ClusterRole, RoleBinding, ClusterRoleBinding and the RunOS
// labels on a Namespace. It has no client-go dependency; objects travel as
// JSON, which kubectl accepts.
package kobj

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// Kinds the compiler emits.
const (
	KindClusterRole        = "ClusterRole"
	KindRoleBinding        = "RoleBinding"
	KindClusterRoleBinding = "ClusterRoleBinding"
	KindNamespace          = "Namespace"
	KindVAP                = "ValidatingAdmissionPolicy"
	KindVAPBinding         = "ValidatingAdmissionPolicyBinding"
	KindConfigMap          = "ConfigMap"
)

// RunOS label keys. They use runos.com/, like every other RunOS Kubernetes
// label. One key used to mean two things; it is two keys now.
const (
	// LabelManaged marks an object roid creates (RoleBindings, ClusterRoles,
	// the deny list and its policy). Retire and drift repair act on objects
	// that carry it. Never set on a namespace: roid does not create one.
	LabelManaged = "runos.com/roid-managed"
	// LabelAccess is the namespace opt-in: a namespace with this label set
	// to true is one roid projects grants into.
	LabelAccess        = "runos.com/roid-access"
	LabelPolicyVersion = "runos.com/policy-version"
	LabelAccount       = "runos.com/account"
	AnnoGrants         = "runos.com/grants"
	// NamespaceSelector is the default label selector for the namespaces
	// roid manages (the applier's ROID_K8S_NS_SELECTOR).
	NamespaceSelector = LabelAccess + "=true"
)

// Rule is one RBAC PolicyRule.
type Rule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// Subject is an RBAC subject.
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	APIGroup  string `json:"apiGroup,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// RoleRef is an RBAC roleRef.
type RoleRef struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

// Object is one compiled object.
type Object struct {
	Kind        string
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
	Rules       []Rule    // ClusterRole
	Aggregation bool      // ClusterRole has an aggregationRule (live objects only)
	Subjects    []Subject // bindings
	RoleRef     *RoleRef  // bindings
	// Spec is the spec of a ValidatingAdmissionPolicy or its binding, in
	// generic JSON form (maps, slices, strings, float64, bool).
	Spec map[string]any `json:",omitempty"`
	// Data is the data of a ConfigMap.
	Data map[string]string `json:",omitempty"`
	// BinaryData is the binaryData of a ConfigMap. Only live objects carry
	// it (the relay ConfigMap holds the gzip body there); a compiled bundle
	// never does, and the applier refuses a bundle object that does.
	BinaryData map[string][]byte `json:",omitempty"`
	// ResourceVersion is set on a live object. It is not part of a bundle.
	ResourceVersion string `json:"-"`
}

// Key names the object: kind/namespace/name.
func (o Object) Key() string { return o.Kind + "/" + o.Namespace + "/" + o.Name }

func apiVersion(kind string) string {
	switch kind {
	case KindNamespace, KindConfigMap:
		return "v1"
	case KindVAP, KindVAPBinding:
		return "admissionregistration.k8s.io/v1"
	}
	return "rbac.authorization.k8s.io/v1"
}

// Manifest renders the object as a Kubernetes manifest.
func (o Object) Manifest() map[string]any {
	meta := map[string]any{"name": o.Name}
	if o.Namespace != "" {
		meta["namespace"] = o.Namespace
	}
	if len(o.Labels) > 0 {
		meta["labels"] = o.Labels
	}
	if len(o.Annotations) > 0 {
		meta["annotations"] = o.Annotations
	}
	m := map[string]any{"apiVersion": apiVersion(o.Kind), "kind": o.Kind, "metadata": meta}
	switch o.Kind {
	case KindClusterRole:
		m["rules"] = o.Rules
	case KindRoleBinding, KindClusterRoleBinding:
		m["subjects"] = o.Subjects
		m["roleRef"] = o.RoleRef
	case KindVAP, KindVAPBinding:
		m["spec"] = o.Spec
	case KindConfigMap:
		d := o.Data
		if d == nil {
			d = map[string]string{}
		}
		m["data"] = d
		if len(o.BinaryData) > 0 {
			m["binaryData"] = o.BinaryData
		}
	}
	return m
}

// JSON renders the manifest.
func (o Object) JSON() []byte {
	b, _ := json.Marshal(o.Manifest())
	return b
}

// ExactPatch is a JSON patch (RFC 6902) that sets the fields RunOS owns
// whole: the spec of a ValidatingAdmissionPolicy or its binding, and the
// data and binaryData of a ConfigMap. A server-side apply cannot do this
// alone. It removes only the list entries and map keys that its own field
// manager owned, so an entry that another manager added stays (a
// hand-added match condition that reads false switches the deny policy
// off). The "add" operation replaces a member that exists. ok=false for
// the other kinds: RBAC rules and subjects are atomic lists, which the
// apply replaces whole, and RunOS owns only its labels on a Namespace.
func (o Object) ExactPatch() (patch []byte, ok bool) {
	type op struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	var ops []op
	switch o.Kind {
	case KindVAP, KindVAPBinding:
		spec := o.Spec
		if spec == nil {
			spec = map[string]any{}
		}
		ops = []op{{"add", "/spec", spec}}
	case KindConfigMap:
		data, bin := o.Data, o.BinaryData
		if data == nil {
			data = map[string]string{}
		}
		if bin == nil {
			bin = map[string][]byte{}
		}
		ops = []op{{"add", "/data", data}, {"add", "/binaryData", bin}}
	default:
		return nil, false
	}
	b, _ := json.Marshal(ops)
	return b, true
}

// List renders objects as one v1 List, for one kubectl call.
func List(objs []Object) []byte {
	items := make([]map[string]any, 0, len(objs))
	for _, o := range objs {
		items = append(items, o.Manifest())
	}
	b, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
	return b
}

type liveMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
}

type liveObj struct {
	Kind            string            `json:"kind"`
	Metadata        liveMeta          `json:"metadata"`
	Rules           []Rule            `json:"rules"`
	AggregationRule json.RawMessage   `json:"aggregationRule"`
	Subjects        []Subject         `json:"subjects"`
	RoleRef         *RoleRef          `json:"roleRef"`
	Spec            map[string]any    `json:"spec"`
	Data            map[string]string `json:"data"`
	BinaryData      map[string][]byte `json:"binaryData"`
}

// FromJSON parses one live object from `kubectl get -o json`.
func FromJSON(b []byte) (Object, error) {
	var l liveObj
	if err := json.Unmarshal(b, &l); err != nil {
		return Object{}, err
	}
	return fromLive(l), nil
}

// ListFromJSON parses a `kubectl get -o json` list.
func ListFromJSON(b []byte) ([]Object, error) {
	var l struct {
		Items []liveObj `json:"items"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	out := make([]Object, 0, len(l.Items))
	for _, it := range l.Items {
		out = append(out, fromLive(it))
	}
	return out, nil
}

func fromLive(l liveObj) Object {
	return Object{
		Kind: l.Kind, Name: l.Metadata.Name, Namespace: l.Metadata.Namespace,
		Labels: l.Metadata.Labels, Annotations: l.Metadata.Annotations,
		Rules: l.Rules, Aggregation: len(l.AggregationRule) > 0 && string(l.AggregationRule) != "null",
		Subjects: l.Subjects, RoleRef: l.RoleRef,
		Spec: l.Spec, Data: l.Data, BinaryData: l.BinaryData, ResourceVersion: l.Metadata.ResourceVersion,
	}
}

func normRules(rs []Rule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		g, res, v, n := slices.Clone(r.APIGroups), slices.Clone(r.Resources), slices.Clone(r.Verbs), slices.Clone(r.ResourceNames)
		sort.Strings(g)
		sort.Strings(res)
		sort.Strings(v)
		sort.Strings(n)
		out = append(out, strings.Join(g, ",")+"|"+strings.Join(res, ",")+"|"+strings.Join(v, ",")+"|"+strings.Join(n, ","))
	}
	sort.Strings(out)
	return out
}

func normSubjects(ss []Subject) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Kind+"|"+s.Name+"|"+s.Namespace)
	}
	sort.Strings(out)
	return out
}

// Diff lists the fields where live differs from desired. For a Namespace
// only the desired labels count: RunOS owns those labels, not the
// namespace. For other kinds RunOS owns the whole object, so an extra label
// or annotation on the live object is not drift, but a missing or changed
// RunOS label is.
func Diff(desired, live Object) []string {
	var d []string
	for k, v := range desired.Labels {
		if live.Labels[k] != v {
			d = append(d, fmt.Sprintf("label %s=%q (want %q)", k, live.Labels[k], v))
		}
	}
	if desired.Kind == KindNamespace {
		sort.Strings(d)
		return d
	}
	for k, v := range desired.Annotations {
		if live.Annotations[k] != v {
			d = append(d, fmt.Sprintf("annotation %s", k))
		}
	}
	switch desired.Kind {
	case KindClusterRole:
		if !slices.Equal(normRules(desired.Rules), normRules(live.Rules)) {
			d = append(d, "rules")
		}
		if live.Aggregation {
			d = append(d, "aggregationRule")
		}
	case KindRoleBinding, KindClusterRoleBinding:
		if live.RoleRef == nil || *live.RoleRef != *desired.RoleRef {
			d = append(d, "roleRef")
		}
		if !slices.Equal(normSubjects(desired.Subjects), normSubjects(live.Subjects)) {
			d = append(d, "subjects")
		}
	case KindVAP, KindVAPBinding:
		// The API server adds defaults to a spec, so only the fields RunOS
		// sets count.
		if !subset(roundTrip(desired.Spec), roundTrip(live.Spec)) {
			d = append(d, "spec")
		}
	case KindConfigMap:
		if len(desired.Data) != len(live.Data) || !maps.Equal(desired.Data, live.Data) ||
			!maps.EqualFunc(desired.BinaryData, live.BinaryData, bytes.Equal) {
			d = append(d, "data")
		}
	}
	sort.Strings(d)
	return d
}

func roundTrip(m map[string]any) any {
	b, _ := json.Marshal(m)
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

// subset reports whether every field of want is in have with the same value.
func subset(want, have any) bool {
	switch w := want.(type) {
	case map[string]any:
		h, ok := have.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range w {
			if !subset(v, h[k]) {
				return false
			}
		}
		return true
	case []any:
		h, ok := have.([]any)
		if !ok || len(h) != len(w) {
			return false
		}
		for i := range w {
			if !subset(w[i], h[i]) {
				return false
			}
		}
		return true
	}
	return want == have
}

// Clone deep-copies an object.
func (o Object) Clone() Object {
	c := o
	c.Labels = maps.Clone(o.Labels)
	c.Annotations = maps.Clone(o.Annotations)
	c.Rules = slices.Clone(o.Rules)
	for i := range c.Rules {
		c.Rules[i].APIGroups = slices.Clone(c.Rules[i].APIGroups)
		c.Rules[i].Resources = slices.Clone(c.Rules[i].Resources)
		c.Rules[i].Verbs = slices.Clone(c.Rules[i].Verbs)
	}
	c.Subjects = slices.Clone(o.Subjects)
	if o.RoleRef != nil {
		r := *o.RoleRef
		c.RoleRef = &r
	}
	if o.Spec != nil {
		var sp map[string]any
		b, _ := json.Marshal(o.Spec)
		_ = json.Unmarshal(b, &sp)
		c.Spec = sp
	}
	c.Data = maps.Clone(o.Data)
	if o.BinaryData != nil {
		c.BinaryData = make(map[string][]byte, len(o.BinaryData))
		for k, v := range o.BinaryData {
			c.BinaryData[k] = bytes.Clone(v)
		}
	}
	return c
}
