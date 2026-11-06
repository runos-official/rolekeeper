package kobj_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/kobj"
)

func managedLabels(version string) map[string]string {
	return map[string]string{kobj.LabelManaged: "true", kobj.LabelPolicyVersion: version, kobj.LabelAccount: "acct-a"}
}

func viewRole() kobj.Object {
	return kobj.Object{
		Kind: kobj.KindClusterRole, Name: "runos:view", Labels: managedLabels("pv-1"),
		Rules: []kobj.Rule{
			{APIGroups: []string{"apps", ""}, Resources: []string{"pods", "deployments"}, Verbs: []string{"list", "get"}},
			{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"get"}},
		},
	}
}

func viewBinding() kobj.Object {
	return kobj.Object{
		Kind: kobj.KindRoleBinding, Name: "runos:view:g:ops", Namespace: "apps", Labels: managedLabels("pv-1"),
		Subjects: []kobj.Subject{{Kind: "Group", Name: "runos:g:ops:view", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: "runos:view"},
	}
}

func TestKeyNamesKindNamespaceAndName(t *testing.T) {
	if got := viewBinding().Key(); got != "RoleBinding/apps/runos:view:g:ops" {
		t.Fatalf("key %q", got)
	}
	if got := viewRole().Key(); got != "ClusterRole//runos:view" {
		t.Fatalf("key %q", got)
	}
}

func TestDiffOfAnObjectAndItsCopyIsEmpty(t *testing.T) {
	for _, o := range []kobj.Object{viewRole(), viewBinding()} {
		if d := kobj.Diff(o, o.Clone()); len(d) != 0 {
			t.Errorf("%s differs from its clone: %v", o.Key(), d)
		}
	}
}

func TestDiffIgnoresTheOrderOfRulesAndTheOrderInsideThem(t *testing.T) {
	want := viewRole()
	live := viewRole()
	live.Rules = []kobj.Rule{live.Rules[1], {APIGroups: []string{"", "apps"}, Resources: []string{"deployments", "pods"}, Verbs: []string{"get", "list"}}}
	if d := kobj.Diff(want, live); len(d) != 0 {
		t.Fatalf("a reordered role differs: %v", d)
	}
}

func TestDiffSeesAChangedRule(t *testing.T) {
	want := viewRole()
	live := viewRole()
	live.Rules[1].Verbs = []string{"get", "delete"}
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"rules"}) {
		t.Fatalf("diff %v", d)
	}
	live = viewRole()
	live.Rules = live.Rules[:1]
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"rules"}) {
		t.Fatalf("a missing rule: diff %v", d)
	}
}

func TestDiffSeesAnAggregationRuleOnTheLiveRole(t *testing.T) {
	live := viewRole()
	live.Aggregation = true
	if d := kobj.Diff(viewRole(), live); !slices.Equal(d, []string{"aggregationRule"}) {
		t.Fatalf("diff %v", d)
	}
}

func TestDiffSeesAChangedMissingOrExtraLabelAsFarAsRunosOwnsIt(t *testing.T) {
	want := viewRole()
	live := viewRole()
	live.Labels[kobj.LabelPolicyVersion] = "pv-0"
	d := kobj.Diff(want, live)
	if len(d) != 1 || !strings.HasPrefix(d[0], `label runos.com/policy-version="pv-0"`) {
		t.Fatalf("diff %v", d)
	}
	live = viewRole()
	delete(live.Labels, kobj.LabelManaged)
	if d := kobj.Diff(want, live); len(d) != 1 || !strings.HasPrefix(d[0], "label runos.com/roid-managed=") {
		t.Fatalf("a missing label: diff %v", d)
	}
	// A label that someone else added is not drift.
	live = viewRole()
	live.Labels["team"] = "x"
	if d := kobj.Diff(want, live); len(d) != 0 {
		t.Fatalf("an extra label is drift: %v", d)
	}
}

func TestDiffSeesAChangedAnnotationButNotAnExtraOne(t *testing.T) {
	want := viewRole()
	want.Annotations = map[string]string{kobj.AnnoGrants: "a"}
	live := want.Clone()
	live.Annotations[kobj.AnnoGrants] = "b"
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"annotation " + kobj.AnnoGrants}) {
		t.Fatalf("diff %v", d)
	}
	live = want.Clone()
	live.Annotations["note"] = "x"
	if d := kobj.Diff(want, live); len(d) != 0 {
		t.Fatalf("an extra annotation is drift: %v", d)
	}
}

func TestDiffOfANamespaceLooksAtTheDesiredLabelsOnly(t *testing.T) {
	want := kobj.Object{Kind: kobj.KindNamespace, Name: "apps", Labels: map[string]string{kobj.LabelAccess: "true"}}
	live := kobj.Object{Kind: kobj.KindNamespace, Name: "apps", Labels: map[string]string{kobj.LabelAccess: "true", "team": "x"}, Annotations: map[string]string{"a": "b"}}
	if d := kobj.Diff(want, live); len(d) != 0 {
		t.Fatalf("diff %v", d)
	}
	live.Labels[kobj.LabelAccess] = "false"
	if d := kobj.Diff(want, live); len(d) != 1 {
		t.Fatalf("diff %v", d)
	}
}

func TestDiffSeesAChangedRoleRefAndMissingRoleRef(t *testing.T) {
	want := viewBinding()
	live := viewBinding()
	live.RoleRef = &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: "runos:edit"}
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"roleRef"}) {
		t.Fatalf("diff %v", d)
	}
	live.RoleRef = nil
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"roleRef"}) {
		t.Fatalf("a binding without roleRef: diff %v", d)
	}
}

func TestDiffSeesChangedSubjectsInAnyOrder(t *testing.T) {
	want := viewBinding()
	want.Subjects = append(want.Subjects, kobj.Subject{Kind: "Group", Name: "runos:cw:view"})
	live := want.Clone()
	slices.Reverse(live.Subjects)
	if d := kobj.Diff(want, live); len(d) != 0 {
		t.Fatalf("reordered subjects differ: %v", d)
	}
	live.Subjects = live.Subjects[:1]
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"subjects"}) {
		t.Fatalf("diff %v", d)
	}
	live = want.Clone()
	live.Subjects[0].Namespace = "other"
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"subjects"}) {
		t.Fatalf("a subject in another namespace: diff %v", d)
	}
}

func TestDiffOfAClusterRoleBindingWorksLikeARoleBinding(t *testing.T) {
	want := viewBinding()
	want.Kind = kobj.KindClusterRoleBinding
	live := want.Clone()
	live.Subjects[0].Name = "runos:g:other:view"
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"subjects"}) {
		t.Fatalf("diff %v", d)
	}
}

func denyPolicy() kobj.Object {
	return kobj.Object{Kind: kobj.KindVAP, Name: "p", Labels: managedLabels("pv-1"), Spec: map[string]any{
		"failurePolicy": "Fail",
		"validations":   []any{map[string]any{"expression": "a", "reason": "Forbidden"}},
	}}
}

func TestDiffOfAPolicySpecCountsOnlyTheFieldsRunosSets(t *testing.T) {
	want := denyPolicy()
	live := denyPolicy()
	// The API server adds defaults to a spec.
	live.Spec["matchPolicy"] = "Equivalent"
	live.Spec["validations"].([]any)[0].(map[string]any)["messageExpression"] = "m"
	if d := kobj.Diff(want, live); len(d) != 0 {
		t.Fatalf("a server default is drift: %v", d)
	}
}

func TestDiffOfAPolicySpecSeesAChangedMissingOrShortenedField(t *testing.T) {
	want := denyPolicy()
	for name, mutate := range map[string]func(spec map[string]any){
		"changed value":  func(s map[string]any) { s["failurePolicy"] = "Ignore" },
		"missing field":  func(s map[string]any) { delete(s, "failurePolicy") },
		"fewer items":    func(s map[string]any) { s["validations"] = []any{} },
		"changed nested": func(s map[string]any) { s["validations"].([]any)[0].(map[string]any)["expression"] = "b" },
		"wrong type":     func(s map[string]any) { s["validations"] = "none" },
		"map for a list": func(s map[string]any) { s["validations"] = map[string]any{} },
	} {
		live := denyPolicy()
		mutate(live.Spec)
		if d := kobj.Diff(want, live); !slices.Equal(d, []string{"spec"}) {
			t.Errorf("%s: diff %v", name, d)
		}
	}
	// A nested map in the live object where the desired has a scalar is a change too.
	want = kobj.Object{Kind: kobj.KindVAPBinding, Name: "b", Spec: map[string]any{"k": "v"}}
	live := kobj.Object{Kind: kobj.KindVAPBinding, Name: "b", Spec: map[string]any{"k": map[string]any{"x": "y"}}}
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"spec"}) {
		t.Fatalf("diff %v", d)
	}
}

func TestDiffOfAConfigMapComparesTheWholeData(t *testing.T) {
	want := kobj.Object{Kind: kobj.KindConfigMap, Name: "c", Namespace: "n", Data: map[string]string{"a": "1"}}
	live := want.Clone()
	if d := kobj.Diff(want, live); len(d) != 0 {
		t.Fatalf("diff %v", d)
	}
	live.Data["b"] = "2"
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"data"}) {
		t.Fatalf("an extra key: diff %v", d)
	}
	live = want.Clone()
	live.Data["a"] = "9"
	if d := kobj.Diff(want, live); !slices.Equal(d, []string{"data"}) {
		t.Fatalf("a changed value: diff %v", d)
	}
}

func TestDiffIsSorted(t *testing.T) {
	want := viewBinding()
	want.Annotations = map[string]string{kobj.AnnoGrants: "a"}
	live := kobj.Object{Kind: kobj.KindRoleBinding, Name: want.Name, Namespace: "apps"}
	d := kobj.Diff(want, live)
	if len(d) < 4 || !slices.IsSorted(d) {
		t.Fatalf("diff %v", d)
	}
}

func TestCloneIsDeep(t *testing.T) {
	o := viewRole()
	o.Annotations = map[string]string{"a": "1"}
	o.Spec = map[string]any{"k": []any{"v"}}
	o.Data = map[string]string{"d": "1"}
	c := o.Clone()
	c.Labels["x"] = "y"
	c.Annotations["a"] = "2"
	c.Rules[0].Verbs[0] = "delete"
	c.Rules[0].APIGroups[0] = "other"
	c.Rules[0].Resources[0] = "secrets"
	c.Spec["k"].([]any)[0] = "changed"
	c.Data["d"] = "2"
	if _, ok := o.Labels["x"]; ok || o.Annotations["a"] != "1" || o.Rules[0].Verbs[0] != "list" || o.Rules[0].APIGroups[0] != "apps" ||
		o.Rules[0].Resources[0] != "pods" || o.Spec["k"].([]any)[0] != "v" || o.Data["d"] != "1" {
		t.Fatalf("the clone shares memory with the original: %+v", o)
	}
	b := viewBinding()
	cb := b.Clone()
	cb.RoleRef.Name = "changed"
	cb.Subjects[0].Name = "changed"
	if b.RoleRef.Name != "runos:view" || b.Subjects[0].Name != "runos:g:ops:view" {
		t.Fatalf("the cloned binding shares memory: %+v", b)
	}
}

func TestCloneOfAnEmptyObjectStaysEmpty(t *testing.T) {
	c := kobj.Object{Kind: kobj.KindClusterRole, Name: "r"}.Clone()
	if c.RoleRef != nil || c.Spec != nil || c.BinaryData != nil || c.Labels != nil {
		t.Fatalf("clone %+v", c)
	}
}

func TestManifestOfEachKind(t *testing.T) {
	cases := []struct {
		o       kobj.Object
		version string
		field   string
	}{
		{viewRole(), "rbac.authorization.k8s.io/v1", "rules"},
		{viewBinding(), "rbac.authorization.k8s.io/v1", "roleRef"},
		{kobj.Object{Kind: kobj.KindNamespace, Name: "apps"}, "v1", ""},
		{kobj.Object{Kind: kobj.KindConfigMap, Name: "c", Namespace: "n"}, "v1", "data"},
		{denyPolicy(), "admissionregistration.k8s.io/v1", "spec"},
		{kobj.Object{Kind: kobj.KindVAPBinding, Name: "b", Spec: map[string]any{}}, "admissionregistration.k8s.io/v1", "spec"},
	}
	for _, c := range cases {
		m := c.o.Manifest()
		if m["apiVersion"] != c.version || m["kind"] != c.o.Kind {
			t.Errorf("%s: apiVersion %v kind %v", c.o.Kind, m["apiVersion"], m["kind"])
		}
		if c.field != "" {
			if _, ok := m[c.field]; !ok {
				t.Errorf("%s: no %s in the manifest", c.o.Kind, c.field)
			}
		}
	}
}

func TestManifestMetadataLeavesOutWhatIsEmpty(t *testing.T) {
	m := kobj.Object{Kind: kobj.KindClusterRole, Name: "r"}.Manifest()
	meta := m["metadata"].(map[string]any)
	if len(meta) != 1 || meta["name"] != "r" {
		t.Fatalf("metadata %v", meta)
	}
	full := kobj.Object{Kind: kobj.KindRoleBinding, Name: "b", Namespace: "n", Labels: map[string]string{"a": "b"}, Annotations: map[string]string{"c": "d"}}.Manifest()["metadata"].(map[string]any)
	for _, k := range []string{"name", "namespace", "labels", "annotations"} {
		if _, ok := full[k]; !ok {
			t.Errorf("metadata lacks %s", k)
		}
	}
}

func TestAConfigMapManifestAlwaysHoldsData(t *testing.T) {
	// An empty deny list must reach the cluster as an empty map, not as a
	// missing field.
	raw := kobj.Object{Kind: kobj.KindConfigMap, Name: "c", Namespace: "n"}.JSON()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if d, ok := m["data"].(map[string]any); !ok || len(d) != 0 {
		t.Fatalf("manifest %s", raw)
	}
}

func TestListRendersOneV1ListInOrder(t *testing.T) {
	raw := kobj.List([]kobj.Object{viewRole(), viewBinding()})
	var l struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Items      []struct {
			Kind string `json:"kind"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	if l.APIVersion != "v1" || l.Kind != "List" || len(l.Items) != 2 || l.Items[0].Kind != "ClusterRole" || l.Items[1].Kind != "RoleBinding" {
		t.Fatalf("list %s", raw)
	}
	empty := string(kobj.List(nil))
	if !strings.Contains(empty, `"items":[]`) {
		t.Fatalf("an empty list: %s", empty)
	}
}

func TestListFromJSONReadsLiveItems(t *testing.T) {
	raw := `{"items":[
	  {"kind":"ClusterRole","metadata":{"name":"r","resourceVersion":"3","labels":{"a":"b"}},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}],"aggregationRule":{"clusterRoleSelectors":[]}},
	  {"kind":"ClusterRole","metadata":{"name":"s"},"aggregationRule":null}
	]}`
	objs, err := kobj.ListFromJSON([]byte(raw))
	if err != nil || len(objs) != 2 {
		t.Fatalf("objs %d err %v", len(objs), err)
	}
	if objs[0].ResourceVersion != "3" || !objs[0].Aggregation || len(objs[0].Rules) != 1 || objs[0].Labels["a"] != "b" {
		t.Fatalf("first %+v", objs[0])
	}
	if objs[1].Aggregation {
		t.Fatal("a null aggregationRule counts as an aggregation")
	}
	if _, err := kobj.ListFromJSON([]byte("{")); err == nil {
		t.Fatal("broken JSON accepted")
	}
	if _, err := kobj.FromJSON([]byte("[")); err == nil {
		t.Fatal("broken JSON accepted")
	}
}

func TestTheResourceVersionOfALiveObjectIsNotPartOfAManifest(t *testing.T) {
	o := viewRole()
	o.ResourceVersion = "99"
	if strings.Contains(string(o.JSON()), "99") {
		t.Fatalf("manifest %s", o.JSON())
	}
	raw, _ := json.Marshal(o)
	if strings.Contains(string(raw), "ResourceVersion") {
		t.Fatalf("object JSON %s", raw)
	}
}
