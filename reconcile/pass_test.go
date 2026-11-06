package reconcile_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/reconcile"
)

func TestFirstPassCreatesEveryObjectAndReportsEachOne(t *testing.T) {
	g := seeded()
	rep := mustPass(t, g, bundle(t, pv1))
	// 5 roles, 1 binding and 3 deny objects are new. A list that was not there
	// is reported once more, because a missing list allows every write.
	if n := rep.Count(reconcile.EvApplied); n != 9 {
		t.Fatalf("applied events: %d, want 9: %v", n, types(rep))
	}
	if rep.Count(reconcile.EvDenyListMissing) != 1 || rep.Count(reconcile.EvRemoved) != 0 {
		t.Fatalf("unexpected events: %v", types(rep))
	}
	for _, e := range []struct{ kind, ns, name string }{
		{kobj.KindClusterRole, "", compile.RoleView},
		{kobj.KindRoleBinding, "apps", "runos:view:g:ops"},
		{kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName},
		{kobj.KindVAP, "", compile.DenyPolicyName},
		{kobj.KindVAPBinding, "", compile.DenyPolicyName},
	} {
		if !g.kube.has(e.kind, e.ns, e.name) {
			t.Errorf("%s %s was not created", e.kind, e.name)
		}
	}
	if got := g.kube.get(kobj.KindNamespace, "", "apps").Labels[kobj.LabelPolicyVersion]; got != pv1 {
		t.Errorf("namespace version label %q", got)
	}
}

func TestTheDenyListIsWrittenBeforeAnythingElse(t *testing.T) {
	g := seeded()
	mustPass(t, g, bundle(t, pv1))
	w := g.kube.writes()
	want := []string{"Create ConfigMap", "Create ValidatingAdmissionPolicy", "Create ValidatingAdmissionPolicyBinding"}
	if len(w) < 3 || !slices.Equal(w[:3], want) {
		t.Fatalf("the first writes are %v, want the list, the policy, the binding", w)
	}
}

func TestASecondPassOfTheSameBundleChangesNothing(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	mustPass(t, g, out)
	g.kube.log = nil
	rep := mustPass(t, g, out)
	if len(rep.Events) != 0 {
		t.Fatalf("a steady pass reported %v", types(rep))
	}
	if w := g.kube.writes(); len(w) != 0 {
		t.Fatalf("a steady pass wrote %v", w)
	}
}

func TestASteadyPassReadsWithListsNotOneGetPerObject(t *testing.T) {
	g := newRig()
	g.kube.put(namespace("apps", true))
	out := bundle(t, pv1)
	for i := 0; i < 30; i++ {
		out.Objects = append(out.Objects, binding("apps", compile.RoleEdit, compile.GroupSubject("team"+string(rune('a'+i%26))+string(rune('a'+i/26)), compile.RoleEdit), pv1))
	}
	mustPass(t, g, out)
	g.kube.log = nil
	mustPass(t, g, out)
	// The deny objects and the namespace are read with a Get. The roles and the
	// bindings come from the lists.
	if n := len(g.kube.calls("Get ")); n > 6 {
		t.Fatalf("%d Get calls for a steady pass of %d objects: %v", n, len(out.Objects), g.kube.calls("Get "))
	}
	if g.kube.calls("Get RoleBinding") != nil || g.kube.calls("Get ClusterRole") != nil {
		t.Fatalf("listed objects were read one by one: %v", g.kube.calls("Get "))
	}
}

func TestAHandEditIsPutBackAndReportedAsDrift(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	mustPass(t, g, out)
	edited := g.kube.get(kobj.KindClusterRole, "", compile.RoleView).Clone()
	edited.Rules = append(edited.Rules, kobj.Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}})
	g.kube.put(edited)

	rep := mustPass(t, g, out)
	if rep.Count(reconcile.EvDrift) != 1 {
		t.Fatalf("events: %v", types(rep))
	}
	e := rep.Events[0]
	if e.Object != "ClusterRole//runos:view" || e.Action != "repaired" || !slices.Equal(e.Fields, []string{"rules"}) {
		t.Fatalf("event %+v", e)
	}
	if got := g.kube.get(kobj.KindClusterRole, "", compile.RoleView); len(got.Rules) != len(compile.FixedRoles(pv1, account)[0].Rules) {
		t.Fatalf("the role still holds the hand edit: %+v", got.Rules)
	}
	if !e.At.Equal(t0) || e.PolicyVersion != pv1 {
		t.Fatalf("event stamp: %+v", e)
	}
}

func TestAHandDeleteOfAnObjectThatWasAppliedIsDrift(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	mustPass(t, g, out)
	delete(g.kube.objs, "RoleBinding/apps/runos:view:g:ops")

	rep := mustPass(t, g, out)
	if got := types(rep); !slices.Equal(got, []string{"projection.drift RoleBinding/apps/runos:view:g:ops"}) {
		t.Fatalf("events %v", got)
	}
	if rep.Events[0].Fields[0] != "deleted" {
		t.Fatalf("fields %v", rep.Events[0].Fields)
	}
	if !g.kube.has(kobj.KindRoleBinding, "apps", "runos:view:g:ops") {
		t.Fatal("the binding was not created again")
	}
}

func TestANewPolicyVersionIsAnUpdateNotDrift(t *testing.T) {
	g := seeded()
	mustPass(t, g, bundle(t, pv1))
	rep := mustPass(t, g, bundle(t, pv2))
	if rep.Count(reconcile.EvDrift) != 0 {
		t.Fatalf("a version change was reported as drift: %v", types(rep))
	}
	if rep.Count(reconcile.EvApplied) == 0 {
		t.Fatalf("no update was reported: %v", types(rep))
	}
	for _, e := range rep.Events {
		if e.Action != "updated" {
			t.Errorf("%s: action %q", e.Object, e.Action)
		}
	}
	if got := g.kube.get(kobj.KindRoleBinding, "apps", "runos:view:g:ops").Labels[kobj.LabelPolicyVersion]; got != pv2 {
		t.Fatalf("binding version %q", got)
	}
}

func TestAChangedRoleRefIsRecreatedBecauseItCannotBeEdited(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	mustPass(t, g, out)
	edited := g.kube.get(kobj.KindRoleBinding, "apps", "runos:view:g:ops").Clone()
	edited.RoleRef = &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: compile.RoleEdit}
	g.kube.put(edited)
	g.kube.log = nil

	rep := mustPass(t, g, out)
	if w := g.kube.writes(); !slices.Equal(w, []string{"Delete RoleBinding", "Create RoleBinding"}) {
		t.Fatalf("writes %v, want delete then create", w)
	}
	if rep.Count(reconcile.EvDrift) != 1 || !slices.Contains(rep.Events[0].Fields, "roleRef") {
		t.Fatalf("events %v", types(rep))
	}
	if g.kube.get(kobj.KindRoleBinding, "apps", "runos:view:g:ops").RoleRef.Name != compile.RoleView {
		t.Fatal("the role reference was not restored")
	}
}

func TestAnObjectThePolicyNoLongerHoldsIsRemoved(t *testing.T) {
	g := seeded()
	full := bundle(t, pv1)
	mustPass(t, g, full)
	// The next bundle holds no binding.
	var next compile.Output
	next.PolicyVersion = pv2
	for _, o := range bundle(t, pv2).Objects {
		if o.Kind != kobj.KindRoleBinding {
			next.Objects = append(next.Objects, o)
		}
	}
	rep := mustPass(t, g, next)
	if rep.Count(reconcile.EvRemoved) != 1 {
		t.Fatalf("events %v", types(rep))
	}
	var e reconcile.Event
	for _, ev := range rep.Events {
		if ev.Type == reconcile.EvRemoved {
			e = ev
		}
	}
	if e.Object != "RoleBinding/apps/runos:view:g:ops" || e.Action != "deleted" || e.Fields[0] != "was "+pv1 {
		t.Fatalf("event %+v", e)
	}
	if g.kube.has(kobj.KindRoleBinding, "apps", "runos:view:g:ops") {
		t.Fatal("the binding stands")
	}
}

func TestARemovalComesBeforeTheCreatesOfTheSamePass(t *testing.T) {
	g := seeded()
	mustPass(t, g, bundle(t, pv1))
	next := bundle(t, pv2)
	// Replace the group by another: one binding goes, one comes.
	for i, o := range next.Objects {
		if o.Kind == kobj.KindRoleBinding {
			next.Objects[i] = binding("apps", compile.RoleView, compile.GroupSubject("dev", compile.RoleView), pv2)
		}
	}
	g.kube.log = nil
	mustPass(t, g, next)
	var del, create = -1, -1
	for i, w := range g.kube.writes() {
		if w == "Delete RoleBinding" {
			del = i
		}
		if w == "Create RoleBinding" {
			create = i
		}
	}
	if del < 0 || create < 0 || del > create {
		t.Fatalf("writes %v: the revoked binding must go before the new one lands", g.kube.writes())
	}
}

func TestADenyObjectIsNeverDeletedEvenWhenTheBundleLeavesItOut(t *testing.T) {
	g := seeded()
	mustPass(t, g, bundle(t, pv1, compile.Deny{Person: "alice", Until: t0.Add(time.Hour)}))
	var noDeny compile.Output
	noDeny.PolicyVersion = pv2
	for _, o := range bundle(t, pv2).Objects {
		if o.Name != compile.DenyPolicyName {
			noDeny.Objects = append(noDeny.Objects, o)
		}
	}
	g.kube.log = nil
	mustPass(t, g, noDeny)
	for _, w := range g.kube.writes() {
		if strings.HasPrefix(w, "Delete ConfigMap") || strings.HasPrefix(w, "Delete ValidatingAdmission") {
			t.Fatalf("a deny object was deleted: %v", g.kube.writes())
		}
	}
	for _, e := range []struct{ kind, ns string }{{kobj.KindConfigMap, compile.DenyNamespace}, {kobj.KindVAP, ""}, {kobj.KindVAPBinding, ""}} {
		if !g.kube.has(e.kind, e.ns, compile.DenyPolicyName) {
			t.Errorf("%s is gone", e.kind)
		}
	}
	if _, ok := g.kube.get(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName).Data["alice"]; !ok {
		t.Error("the live list lost its entry")
	}
}

func TestAnObjectThatIsNotManagedIsLeftAlone(t *testing.T) {
	g := seeded()
	other := kobj.Object{Kind: kobj.KindClusterRole, Name: "someone-elses", Labels: map[string]string{"app": "x"}}
	g.kube.put(other)
	mustPass(t, g, bundle(t, pv1))
	if !g.kube.has(kobj.KindClusterRole, "", "someone-elses") {
		t.Fatal("an object without the managed label was deleted")
	}
}

func TestANamespaceThatDoesNotExistIsNotCreated(t *testing.T) {
	g := newRig() // the cluster has no namespace "apps"
	mustPass(t, g, bundle(t, pv1))
	if g.kube.has(kobj.KindNamespace, "", "apps") {
		t.Fatal("the projection created a namespace")
	}
}

func TestANamespaceWithoutTheOptInLabelIsAdopted(t *testing.T) {
	g := newRig()
	g.kube.put(namespace("apps", false))
	rep := mustPass(t, g, bundle(t, pv1))
	var adopted []reconcile.Event
	for _, e := range rep.Events {
		if e.Action == "adopted" {
			adopted = append(adopted, e)
		}
	}
	if len(adopted) != 1 || adopted[0].Type != reconcile.EvApplied || adopted[0].Object != "Namespace//apps" {
		t.Fatalf("events %v", types(rep))
	}
}

func TestEventsReachTheSinkAsWellAsTheReport(t *testing.T) {
	g := seeded()
	rep := mustPass(t, g, bundle(t, pv1))
	if len(g.sink.events) != len(rep.Events) || len(rep.Events) == 0 {
		t.Fatalf("sink %d, report %d", len(g.sink.events), len(rep.Events))
	}
	g.r.Sink = nil
	g.kube.objs = map[string]kobj.Object{}
	g.kube.put(namespace("apps", true))
	if _, err := g.pass(bundle(t, pv1), "apps"); err != nil {
		t.Fatalf("a nil sink broke the pass: %v", err)
	}
}

func TestReportCountsEventsOfOneType(t *testing.T) {
	rep := reconcile.Report{Events: []reconcile.Event{{Type: reconcile.EvDrift}, {Type: reconcile.EvApplied}, {Type: reconcile.EvDrift}}}
	if rep.Count(reconcile.EvDrift) != 2 || rep.Count(reconcile.EvRemoved) != 0 {
		t.Fatalf("counts: %d %d", rep.Count(reconcile.EvDrift), rep.Count(reconcile.EvRemoved))
	}
}

func TestAKubeErrorStopsThePassAndComesBack(t *testing.T) {
	for _, call := range []string{"Get", "Create", "ListManaged", "ListRoleBindings"} {
		t.Run(call, func(t *testing.T) {
			g := seeded()
			boom := errBoom(call)
			g.kube.fail[call] = boom
			if _, err := g.pass(bundle(t, pv1), "apps"); !errors.Is(err, boom) {
				t.Fatalf("err %v, want the kube error", err)
			}
		})
	}
	t.Run("Delete", func(t *testing.T) {
		g := seeded()
		mustPass(t, g, bundle(t, pv1))
		g.kube.fail["Delete"] = errBoom("Delete")
		next := compile.Output{PolicyVersion: pv2}
		for _, o := range bundle(t, pv2).Objects {
			if o.Kind != kobj.KindRoleBinding {
				next.Objects = append(next.Objects, o)
			}
		}
		if _, err := g.pass(next, "apps"); err == nil {
			t.Fatal("a failed delete was not reported")
		}
	})
	t.Run("Replace", func(t *testing.T) {
		g := seeded()
		mustPass(t, g, bundle(t, pv1))
		g.kube.fail["Replace"] = errBoom("Replace")
		if _, err := g.pass(bundle(t, pv2), "apps"); err == nil {
			t.Fatal("a failed replace was not reported")
		}
	})
}
