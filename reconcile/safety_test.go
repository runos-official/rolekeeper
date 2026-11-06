package reconcile_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/reconcile"
)

// withWildcardRole returns a bundle whose view role holds a wildcard, which
// Lint refuses.
func withWildcardRole(t *testing.T, pv string, deny ...compile.Deny) compile.Output {
	t.Helper()
	out := bundle(t, pv, deny...)
	for i, o := range out.Objects {
		if o.Kind == kobj.KindClusterRole && o.Name == compile.RoleView {
			o = o.Clone()
			o.Rules = append(o.Rules, kobj.Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}})
			out.Objects[i] = o
		}
	}
	return out
}

func TestABundleThatFailsLintAppliesNothingButTheDenyList(t *testing.T) {
	g := seeded()
	mustPass(t, g, bundle(t, pv1))
	g.kube.log = nil
	bad := withWildcardRole(t, pv2, compile.Deny{Person: "alice", Until: t0.Add(time.Hour)})

	rep, err := g.pass(bad, "apps")
	if !errors.Is(err, reconcile.ErrLint) {
		t.Fatalf("err %v, want ErrLint", err)
	}
	if rep.Count(reconcile.EvRefused) != 1 {
		t.Fatalf("events %v", types(rep))
	}
	// The one refused event names every finding.
	if len(rep.Events[0].Fields) == 0 {
		t.Fatal("the refusal names no finding")
	}
	if _, ok := g.kube.get(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName).Data["alice"]; !ok {
		t.Fatal("a lint finding elsewhere in the bundle stopped the deny list")
	}
	for _, w := range g.kube.writes() {
		if w == "Delete RoleBinding" || w == "Create ClusterRole" || w == "Replace ClusterRole" {
			t.Fatalf("the refused bundle changed %s", w)
		}
	}
	if got := g.kube.get(kobj.KindClusterRole, "", compile.RoleView); slices.ContainsFunc(got.Rules, func(r kobj.Rule) bool { return slices.Contains(r.Verbs, "*") }) {
		t.Fatal("the escalating role was applied")
	}
}

func TestADenyListThatFailsItsOwnLintLandsNothing(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	for i, o := range out.Objects {
		if o.Kind == kobj.KindConfigMap {
			o = o.Clone()
			o.Data = map[string]string{"alice": "not a time"}
			out.Objects[i] = o
		}
	}
	rep, err := g.pass(out, "apps")
	if !errors.Is(err, reconcile.ErrLint) {
		t.Fatalf("err %v", err)
	}
	if rep.Count(reconcile.EvRefused) != 1 {
		t.Fatalf("events %v", types(rep))
	}
	if w := g.kube.writes(); len(w) != 0 {
		t.Fatalf("a bundle with a broken deny list wrote %v", w)
	}
}

func TestAnObjectOutsideTheNamedNamespacesIsRefused(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	out.Objects = append(out.Objects, binding("elsewhere", compile.RoleView, compile.GroupSubject("ops", compile.RoleView), pv1))
	rep, err := g.pass(out, "apps")
	if !errors.Is(err, reconcile.ErrLint) || rep.Count(reconcile.EvRefused) != 1 {
		t.Fatalf("err %v, events %v", err, types(rep))
	}
	if g.kube.has(kobj.KindRoleBinding, "elsewhere", "runos:view:g:ops") {
		t.Fatal("the out-of-scope binding was applied")
	}
}

func TestADenyOnlyProjectionAppliesTheDenyListAndRemovesNothing(t *testing.T) {
	g := seeded()
	mustPass(t, g, bundle(t, pv1))
	g.kube.log = nil

	refused := compile.Output{PolicyVersion: pv2, DenyOnly: true, Objects: denyObjects(t, pv2, compile.Deny{Person: "alice", Until: t0.Add(time.Hour)})}
	rep, err := g.pass(refused, "apps")
	if !errors.Is(err, reconcile.ErrRefused) {
		t.Fatalf("err %v, want ErrRefused", err)
	}
	if rep.Count(reconcile.EvDenyOnly) != 1 {
		t.Fatalf("events %v", types(rep))
	}
	if !g.kube.has(kobj.KindRoleBinding, "apps", "runos:view:g:ops") || !g.kube.has(kobj.KindClusterRole, "", compile.RoleView) {
		t.Fatal("a refused projection removed the people's bindings")
	}
	if _, ok := g.kube.get(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName).Data["alice"]; !ok {
		t.Fatal("the cut did not land")
	}
	for _, w := range g.kube.writes() {
		if w == "Delete RoleBinding" || w == "Delete ClusterRole" {
			t.Fatalf("a refused projection ran %s", w)
		}
	}
}

func TestPassDenyListOnlyAppliesTheDenyObjectsOfABundle(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1, compile.Deny{Person: "alice", Until: t0.Add(time.Hour)})
	rep, err := g.r.PassDenyListOnly(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Count(reconcile.EvDenyOnly) != 1 {
		t.Fatalf("events %v", types(rep))
	}
	if g.kube.has(kobj.KindClusterRole, "", compile.RoleView) || g.kube.has(kobj.KindRoleBinding, "apps", "runos:view:g:ops") {
		t.Fatal("something other than the deny list was applied")
	}
	if !g.kube.has(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName) {
		t.Fatal("the list was not applied")
	}
}

func TestPassDenyListOnlyRefusesDenyObjectsThatFailLint(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	for i, o := range out.Objects {
		if o.Kind == kobj.KindVAP {
			o = o.Clone()
			o.Spec = map[string]any{"failurePolicy": "Ignore"}
			out.Objects[i] = o
		}
	}
	rep, err := g.r.PassDenyListOnly(context.Background(), out)
	if !errors.Is(err, reconcile.ErrLint) || rep.Count(reconcile.EvRefused) != 1 {
		t.Fatalf("err %v events %v", err, types(rep))
	}
	if w := g.kube.writes(); len(w) != 0 {
		t.Fatalf("wrote %v", w)
	}
}

func TestDenyObjectsSelectsThePolicyTheListAndTheBindingInThatOrder(t *testing.T) {
	got := reconcile.DenyObjects(bundle(t, pv1).Objects)
	kinds := []string{}
	for _, o := range got {
		kinds = append(kinds, o.Kind)
	}
	want := []string{kobj.KindConfigMap, kobj.KindVAP, kobj.KindVAPBinding}
	if !slices.Equal(kinds, want) {
		t.Fatalf("got %v, want %v", kinds, want)
	}
	if got := reconcile.DenyObjects(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestAMissingDenyListIsWrittenBackAndAlwaysReported(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1, compile.Deny{Person: "alice", Until: t0.Add(time.Hour)})
	mustPass(t, g, out)
	delete(g.kube.objs, "ConfigMap/runos/"+compile.DenyPolicyName)

	rep := mustPass(t, g, out)
	if rep.Count(reconcile.EvDenyListMissing) != 1 {
		t.Fatalf("events %v", types(rep))
	}
	if _, ok := g.kube.get(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName).Data["alice"]; !ok {
		t.Fatal("the list was written back without its entry")
	}
}

func TestRepairDenyListWritesBackOnlyAMissingList(t *testing.T) {
	g := seeded()
	objs := bundle(t, pv1, compile.Deny{Person: "alice", Until: t0.Add(time.Hour)}).Objects

	rep, err := g.r.RepairDenyList(context.Background(), objs)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Count(reconcile.EvDenyListMissing) != 1 || !g.kube.has(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName) {
		t.Fatalf("events %v", types(rep))
	}
	if g.kube.has(kobj.KindVAP, "", compile.DenyPolicyName) || g.kube.has(kobj.KindClusterRole, "", compile.RoleView) {
		t.Fatal("RepairDenyList wrote more than the list")
	}

	// A list that exists is left alone, even when it differs.
	g.kube.log = nil
	rep, err = g.r.RepairDenyList(context.Background(), append(slices.Clone(objs[:0]), withEmptyList(objs)...))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events) != 0 || len(g.kube.writes()) != 0 {
		t.Fatalf("events %v writes %v", types(rep), g.kube.writes())
	}
	if _, ok := g.kube.get(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName).Data["alice"]; !ok {
		t.Fatal("the live list was overwritten by an older one")
	}
}

func withEmptyList(objs []kobj.Object) []kobj.Object {
	out := slices.Clone(objs)
	for i, o := range out {
		if o.Kind == kobj.KindConfigMap {
			o = o.Clone()
			o.Data = map[string]string{}
			out[i] = o
		}
	}
	return out
}

func TestRepairDenyListReturnsAKubeError(t *testing.T) {
	g := seeded()
	g.kube.fail["Get"] = errBoom("get")
	if _, err := g.r.RepairDenyList(context.Background(), bundle(t, pv1).Objects); err == nil {
		t.Fatal("the error was swallowed")
	}
}

func TestTheCanaryRidesOnTheListAndItsTurnoverIsNotDrift(t *testing.T) {
	g := seeded()
	g.r.Canary = compile.DenyCanaries[0]
	out := bundle(t, pv1)
	mustPass(t, g, out)
	list := g.kube.get(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	if list.Data[compile.DenyCanaries[0]] != compile.CanaryUntil {
		t.Fatalf("the canary is not on the list: %v", list.Data)
	}

	g.r.Canary = compile.DenyCanaries[1]
	g.kube.log = nil
	rep := mustPass(t, g, out)
	if len(rep.Events) != 0 {
		t.Fatalf("a canary turnover was reported: %v", types(rep))
	}
	if got := g.kube.get(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName).Data; got[compile.DenyCanaries[1]] == "" {
		t.Fatalf("the new canary was not written: %v", got)
	}
	if !slices.Equal(g.kube.calls("Replace"), []string{"Replace ConfigMap"}) {
		t.Fatalf("calls %v", g.kube.calls("Replace"))
	}
}

func TestACanaryDoesNotHideARealChangeToTheList(t *testing.T) {
	g := seeded()
	g.r.Canary = compile.DenyCanaries[0]
	mustPass(t, g, bundle(t, pv1))
	rep := mustPass(t, g, bundle(t, pv1, compile.Deny{Person: "alice", Until: t0.Add(time.Hour)}))
	if rep.Count(reconcile.EvDrift) != 1 {
		t.Fatalf("a change of the list beside the canary was not reported: %v", types(rep))
	}
}

func TestAMissingDenyPolicyIsReportedOnceAndNeverCreatedWhenTheInstallerOwnsIt(t *testing.T) {
	g := seeded()
	g.r.KeepDenyPolicy = true
	out := bundle(t, pv1)

	rep := mustPass(t, g, out)
	if rep.Count(reconcile.EvDenyPolicyMissing) != 2 {
		t.Fatalf("events %v", types(rep))
	}
	if g.kube.has(kobj.KindVAP, "", compile.DenyPolicyName) || g.kube.has(kobj.KindVAPBinding, "", compile.DenyPolicyName) {
		t.Fatal("the reconciler created the policy")
	}
	if !g.kube.has(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName) {
		t.Fatal("the list is not written when the policy is missing")
	}

	again := mustPass(t, g, out)
	if again.Count(reconcile.EvDenyPolicyMissing) != 0 {
		t.Fatalf("the gap was reported twice: %v", types(again))
	}

	// The installer puts the policy back; it is seen, and a later loss reports again.
	for _, o := range denyObjects(t, pv1) {
		if o.Kind != kobj.KindConfigMap {
			g.kube.put(o)
		}
	}
	mustPass(t, g, out)
	delete(g.kube.objs, "ValidatingAdmissionPolicy//"+compile.DenyPolicyName)
	if rep := mustPass(t, g, out); rep.Count(reconcile.EvDenyPolicyMissing) != 1 {
		t.Fatalf("a second loss was not reported: %v", types(rep))
	}
}

func TestWithoutKeepDenyPolicyAMissingPolicyIsCreated(t *testing.T) {
	g := seeded()
	mustPass(t, g, bundle(t, pv1))
	if !g.kube.has(kobj.KindVAP, "", compile.DenyPolicyName) {
		t.Fatal("the policy was not created")
	}
}

// hand-made bindings in a managed namespace

func foreignBinding(name string, role string, subjects ...kobj.Subject) kobj.Object {
	return kobj.Object{
		Kind: kobj.KindRoleBinding, Name: name, Namespace: "apps",
		Subjects: subjects, RoleRef: &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: role},
	}
}

func TestAHandMadeBindingThatNamesARunosSubjectIsRemoved(t *testing.T) {
	g := seeded()
	g.kube.put(foreignBinding("sneaky", "view", kobj.Subject{Kind: "Group", Name: "runos:g:ops:view"}))
	rep := mustPass(t, g, bundle(t, pv1))
	if rep.Count(reconcile.EvForeign) != 1 {
		t.Fatalf("events %v", types(rep))
	}
	var e reconcile.Event
	for _, ev := range rep.Events {
		if ev.Type == reconcile.EvForeign {
			e = ev
		}
	}
	if e.Object != "RoleBinding/apps/sneaky" || !slices.Equal(e.Fields, []string{"Group runos:g:ops:view"}) || e.Action != "deleted" {
		t.Fatalf("event %+v", e)
	}
	if g.kube.has(kobj.KindRoleBinding, "apps", "sneaky") {
		t.Fatal("the foreign binding stands")
	}
}

func TestAHandMadeBindingOfAFixedRoleToAUserIsRemovedWhateverTheUserIsCalled(t *testing.T) {
	g := seeded()
	g.kube.put(foreignBinding("by-hand", compile.RoleEdit, kobj.Subject{Kind: "User", Name: "mallory"}))
	rep := mustPass(t, g, bundle(t, pv1))
	if rep.Count(reconcile.EvForeign) != 1 || g.kube.has(kobj.KindRoleBinding, "apps", "by-hand") {
		t.Fatalf("events %v", types(rep))
	}
}

func TestAWorkloadBindingAndAnUnrelatedBindingStay(t *testing.T) {
	g := seeded()
	g.kube.put(
		foreignBinding("workload", compile.RoleView, kobj.Subject{Kind: "ServiceAccount", Name: "app", Namespace: "apps"}),
		foreignBinding("builtin", "view", kobj.Subject{Kind: "User", Name: "alice"}),
	)
	rep := mustPass(t, g, bundle(t, pv1))
	if rep.Count(reconcile.EvForeign) != 0 {
		t.Fatalf("events %v", types(rep))
	}
	if !g.kube.has(kobj.KindRoleBinding, "apps", "workload") || !g.kube.has(kobj.KindRoleBinding, "apps", "builtin") {
		t.Fatal("an unrelated binding was removed")
	}
}

func stamped(name, stamp string) kobj.Object {
	b := foreignBinding(name, compile.RoleView, kobj.Subject{Kind: "Group", Name: "runos:g:ops:view"})
	b.Annotations = map[string]string{compile.BreakGlassStamp: stamp}
	return b
}

func TestABreakGlassBindingStandsUntilItsStampExpires(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	g.kube.put(stamped("emergency", t0.Add(10*time.Minute).Format(time.RFC3339)))

	if rep := mustPass(t, g, out); rep.Count(reconcile.EvBreakGlassExpired) != 0 || !g.kube.has(kobj.KindRoleBinding, "apps", "emergency") {
		t.Fatalf("a live break-glass binding was touched: %v", types(rep))
	}
	g.now = t0.Add(11 * time.Minute)
	rep := mustPass(t, g, out)
	if rep.Count(reconcile.EvBreakGlassExpired) != 1 || g.kube.has(kobj.KindRoleBinding, "apps", "emergency") {
		t.Fatalf("an expired stamp did not remove the binding: %v", types(rep))
	}
}

func TestABreakGlassBindingNeverStandsLongerThanTheMaximumFromFirstSight(t *testing.T) {
	g := seeded()
	out := bundle(t, pv1)
	// The stamp claims a day, the maximum is shorter.
	g.kube.put(stamped("emergency", t0.Add(24*time.Hour).Format(time.RFC3339)))
	mustPass(t, g, out)
	g.now = t0.Add(compile.BreakGlassStampMax - time.Second)
	if rep := mustPass(t, g, out); rep.Count(reconcile.EvBreakGlassExpired) != 0 {
		t.Fatalf("removed too early: %v", types(rep))
	}
	g.now = t0.Add(compile.BreakGlassStampMax)
	if rep := mustPass(t, g, out); rep.Count(reconcile.EvBreakGlassExpired) != 1 {
		t.Fatalf("not removed at the maximum: %v", types(rep))
	}
}

func TestABreakGlassStampThatIsNotATimeExpiresAtOnce(t *testing.T) {
	g := seeded()
	g.kube.put(stamped("emergency", "next week"))
	rep := mustPass(t, g, bundle(t, pv1))
	if rep.Count(reconcile.EvBreakGlassExpired) != 1 || g.kube.has(kobj.KindRoleBinding, "apps", "emergency") {
		t.Fatalf("events %v", types(rep))
	}
}
