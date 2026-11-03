package applier_test

// The in-cluster applier.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/bundle"
	"github.com/runos-official/rolekeeper/internal/compile"
	"github.com/runos-official/rolekeeper/internal/kobj"
)

func (r *rig) r8k8sHas(kind, ns, name string) bool {
	_, ok, _ := r.kube.Get(context.Background(), kind, ns, name)
	return ok
}

// The floor is read from its ConfigMap at every pass and nowhere else.
// When it is deleted (or edited to a lower version) while the applier
// runs, the next pass counts as a fresh start, and the fresh-start rule
// only compares the bundle's signing time with the process start. Any
// bundle signed since the process started, with a version below the one
// it applied, is then applied: here a captured v1 brings back a binding
// that v2 revoked. The applier knows the floor it applied itself; it must
// keep refusing anything below it.
func TestReview8K8sADeletedFloorLetsNoOlderBundleBack(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	a := r.applier(r.now.Add(-time.Minute))
	r.offer(1, binding("alice"))
	v1 := r.roid.next // captured on the wire
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("v1: %+v %v", res, err)
	}
	r.now = r.now.Add(time.Minute)
	r.offer(2) // alice's grant revoked
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("v2: %+v %v", res, err)
	}
	if r.r8k8sHas(kobj.KindRoleBinding, "apps", "runos:view:u:alice") {
		t.Fatal("setup: the revoke did not remove the binding")
	}
	if err := os.Remove(r.floor.Path); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(10 * time.Second)
	r.roid.next = v1 // the replay
	_, err := a.RunOnce(ctx)
	if !errors.Is(err, bundle.ErrStale) || r.r8k8sHas(kobj.KindRoleBinding, "apps", "runos:view:u:alice") {
		t.Fatalf("with its floor deleted, the running applier took v1 after applying v2 (err %v): the revoked binding is back: %v",
			err, r.r8k8sHas(kobj.KindRoleBinding, "apps", "runos:view:u:alice"))
	}
}

// The applier reports status only on a change, a refusal or the
// heartbeat, because the applier polls every 2 s and roid's service
// listener allows 60 calls a minute per service. A deny-only bundle (roid
// refused the projection, for example over one grant RBAC cannot express)
// emits projection.deny_only on every pass, so every pass is reported:
// one fetch and one report every 2 s is the whole limit, and roid writes a
// k8s.bundle.applied audit record every 2 s for as long as it lasts.
func TestReview8K8sAnUnchangedDenyOnlyBundleIsNotReportedEveryPass(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	deny, err := compile.DenyObjects("pv-1", "acct-a", nil, r.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range deny {
		if compile.IsKeptDenyObject(o.Kind, o.Name) {
			_ = r.kube.Create(ctx, o) // the installer wrote the policy and its binding
		}
	}
	raw, err := bundle.Seal(ctx, r.issuer, bundle.Bundle{Account: "acct-a", Cluster: "cl-1", Version: 1, PolicyVersion: "pv-1",
		Namespaces: []string{"apps"}, Objects: deny, DenyOnly: true, IssuedAt: r.now}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.roid.next = raw
	a := r.applier(r.now.Add(-time.Minute))
	a.ReportEvery = 5 * time.Minute
	for range 5 {
		if _, err := a.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		r.now = r.now.Add(2 * time.Second)
	}
	if len(r.roid.reports) != 1 {
		t.Fatalf("five passes of one unchanged deny-only bundle sent %d status reports, want 1 (events %v)", len(r.roid.reports), r.roid.reports[len(r.roid.reports)-1].Events)
	}
}

// Lint refuses bindings in the protected namespaces only. A signed
// bundle whose RoleBinding names a namespace outside the bundle's own
// managed set is applied, though the compiler never emits one: the
// applier is the last check when the issuer is wrong, and it does
// not hold the bundle to the namespaces it sent.
func TestReview8K8sABindingOutsideTheManagedNamespacesIsRefused(t *testing.T) {
	r := newRig(t)
	stray := binding("alice")
	stray.Namespace = "payments" // the bundle manages only "apps"
	r.offer(1, stray)
	a := r.applier(r.now.Add(-time.Minute))
	_, err := a.RunOnce(context.Background())
	if r.r8k8sHas(kobj.KindRoleBinding, "payments", stray.Name) {
		t.Fatalf("the applier wrote a RoleBinding into payments, a namespace the bundle does not manage (err %v)", err)
	}
}

// The deny policy and its binding are kept when a bundle leaves them
// out (IsKeptDenyObject), but the list itself is not: a bundle that does
// not carry runos/runos-deny-writes makes the prune delete it, and a
// missing list allows every write, so the people on it can write again.
// roid always sends the list, so this needs a wrong issuer, which is what
// the applier's own checks are for. A bundle without the list must be
// refused, or the list kept.
func TestReview8K8sABundleWithoutTheDenyListDoesNotDeleteIt(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	deny, err := compile.DenyObjects("pv-1", "acct-a", []compile.Deny{{Person: "mallory", Until: r.now.Add(16 * time.Minute)}}, r.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range deny {
		if compile.IsKeptDenyObject(o.Kind, o.Name) {
			_ = r.kube.Create(ctx, o)
		}
	}
	a := r.applier(r.now.Add(-time.Minute))
	r.offer(1, append(deny, binding("alice"))...)
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("v1: %+v %v", res, err)
	}
	if !r.r8k8sHas(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName) {
		t.Fatal("setup: the deny list was not written")
	}
	r.now = r.now.Add(time.Minute)
	r.offer(2, binding("alice")) // no deny objects
	_, err = a.RunOnce(ctx)
	if !r.r8k8sHas(kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName) {
		t.Fatalf("a bundle without the deny list made the applier delete %s/%s (err %v): mallory, cut for 16 minutes, can write again",
			compile.DenyNamespace, compile.DenyPolicyName, err)
	}
}
