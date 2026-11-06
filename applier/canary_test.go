package applier_test

// Deny safety in the applier: a missing deny list is written back and
// reported, also when roid cannot be reached; the deny policy is never
// re-created; and after each pass a canary check asks the API server
// whether the list really cuts.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/kubeapi"
)

// fakeProbe is the API server's admission view of the deny list: the live
// list, a frozen copy (a re-created policy), or no policy at all.
type fakeProbe struct {
	mu    sync.Mutex
	kube  *fakeKube
	mode  string // "", "frozen", "nopolicy", "rbac"
	snap  map[string]string
	users []string
}

func (p *fakeProbe) freeze() {
	cm, _, _ := p.kube.Get(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	p.mu.Lock()
	p.mode, p.snap = "frozen", cm.Data
	p.mu.Unlock()
}

func (p *fakeProbe) DenyProbe(ctx context.Context, user, ns string) (kubeapi.ProbeResult, string, error) {
	p.mu.Lock()
	p.users = append(p.users, user)
	mode, view := p.mode, p.snap
	p.mu.Unlock()
	switch mode {
	case "nopolicy":
		return kubeapi.ProbeAllowed, "", nil
	case "rbac":
		return kubeapi.ProbeOther, "403 cannot create resource configmaps", nil
	case "":
		cm, _, _ := p.kube.Get(ctx, kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
		view = cm.Data
	}
	if _, ok := view[strings.TrimPrefix(user, compile.UserPrefix)]; ok {
		return kubeapi.ProbeDenied, "ValidatingAdmissionPolicy 'runos-deny-writes' denied request", nil
	}
	return kubeapi.ProbeAllowed, "", nil
}

// denyRig is a cluster as the installer leaves it (policy, empty list,
// binding) and a bundle that carries the deny objects.
func denyRig(t *testing.T) (*rig, *applier.Applier, *fakeProbe) {
	t.Helper()
	r := newRig(t)
	objs, err := compile.DenyObjects(compile.InstallPolicyVersion, "acct-a", nil, r.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		_ = r.kube.Create(context.Background(), o)
	}
	deny, _ := compile.DenyObjects("pv-1", "acct-a", nil, r.now)
	r.offer(1, append(deny, binding("alice"))...)
	a := r.applier(r.now.Add(-time.Minute))
	p := &fakeProbe{kube: r.kube}
	a.Probe, a.CanaryNamespace = p, "roid-k8s-applier"
	a.CanaryEvery, a.CanaryGrace = 30*time.Second, 10*time.Second
	return r, a, p
}

func (r *rig) list() map[string]string {
	cm, _, _ := r.kube.Get(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	return cm.Data
}

func (r *rig) last() applier.Status {
	r.roid.mu.Lock()
	defer r.roid.mu.Unlock()
	return r.roid.reports[len(r.roid.reports)-1]
}

func (r *rig) pass(a *applier.Applier, step time.Duration) (applier.Result, error) {
	res, err := a.RunOnce(context.Background())
	r.now = r.now.Add(step)
	return res, err
}

func canaryOn(t *testing.T, d map[string]string) string {
	t.Helper()
	var on []string
	for _, c := range compile.DenyCanaries {
		if d[c] != "" {
			on = append(on, c)
		}
	}
	if len(on) != 1 {
		t.Fatalf("want one canary on the list, got %v (%v)", on, d)
	}
	return on[0]
}

// A healthy policy: the listed canary is refused and the other is not; the
// canary turns over, and the check still passes.
func TestTheCanaryPassesAndTurnsOver(t *testing.T) {
	r, a, p := denyRig(t)
	if res, err := r.pass(a, 2*time.Second); err != nil || res.Canary != applier.CanaryOK {
		t.Fatalf("first pass: %+v %v", res, err)
	}
	first := canaryOn(t, r.list())
	if st := r.last(); st.Canary != applier.CanaryOK {
		t.Fatalf("status %+v", st)
	}
	if len(p.users) != 2 || p.users[0] == p.users[1] {
		t.Fatalf("probed %v, want both canaries", p.users)
	}
	r.now = r.now.Add(31 * time.Second)
	for range 3 {
		if res, err := r.pass(a, 2*time.Second); err != nil || res.Canary != applier.CanaryOK {
			t.Fatalf("pass after the turnover: %+v %v", res, err)
		}
	}
	if canaryOn(t, r.list()) == first {
		t.Fatal("the canary did not turn over")
	}
}

// A re-created policy can keep an old copy of its list. The canary check
// finds it at the next turnover and reports it once the grace has passed.
func TestABlindPolicyFailsTheCanary(t *testing.T) {
	r, a, p := denyRig(t)
	if _, err := r.pass(a, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	p.freeze()
	r.now = r.now.Add(31 * time.Second)
	res, _ := r.pass(a, 2*time.Second) // ok against the frozen copy; the canary turns over
	if res.Canary != applier.CanaryOK {
		t.Fatalf("before the turnover: %+v", res)
	}
	res, _ = r.pass(a, 2*time.Second) // the new canary is on the list; the policy does not see it
	if res.Canary != applier.CanaryOK {
		t.Fatalf("a failure inside the grace was reported: %+v", res)
	}
	r.now = r.now.Add(10 * time.Second)
	res, _ = r.pass(a, 2*time.Second)
	st := r.last()
	if res.Canary != applier.CanaryFailing || st.Canary != applier.CanaryFailing || !strings.Contains(st.CanaryReason, "does not see changes") {
		t.Fatalf("a blind policy was not reported: %+v / %+v", res, st)
	}
	// Restarting kube-apiserver makes the policy see the list again.
	p.mu.Lock()
	p.mode = ""
	p.mu.Unlock()
	if res, _ = r.pass(a, 2*time.Second); res.Canary != applier.CanaryOK || r.last().Canary != applier.CanaryOK {
		t.Fatalf("after the fix: %+v %+v", res, r.last())
	}
}

// No policy (or no binding): the listed canary may write.
func TestAMissingPolicyFailsTheCanaryAndIsNotRecreated(t *testing.T) {
	r, a, p := denyRig(t)
	if _, err := r.pass(a, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	_ = r.kube.Delete(context.Background(), kobj.KindVAP, "", compile.DenyPolicyName)
	p.mu.Lock()
	p.mode = "nopolicy"
	p.mu.Unlock()
	if _, err := r.pass(a, 11*time.Second); err != nil {
		t.Fatalf("a missing policy stopped the pass: %v", err)
	}
	res, _ := r.pass(a, 2*time.Second)
	if _, ok, _ := r.kube.Get(context.Background(), kobj.KindVAP, "", compile.DenyPolicyName); ok {
		t.Fatal("the applier re-created the deny policy")
	}
	st := r.last()
	if res.Canary != applier.CanaryFailing || !strings.Contains(st.CanaryReason, "does not cut") {
		t.Fatalf("status %+v", st)
	}
	if st.Events["projection.deny_policy_missing"] == 0 && r.roid.reports[len(r.roid.reports)-2].Events["projection.deny_policy_missing"] == 0 {
		t.Fatalf("the missing policy was not reported: %+v", r.roid.reports)
	}
}

// A canary that RBAC refuses proves nothing: it fails with the reason.
func TestACanaryRefusedByRBACFails(t *testing.T) {
	r, a, p := denyRig(t)
	p.mode = "rbac"
	_, _ = r.pass(a, 11*time.Second)
	if res, _ := r.pass(a, 2*time.Second); res.Canary != applier.CanaryFailing || !strings.Contains(r.last().CanaryReason, "cannot create") {
		t.Fatalf("%+v %+v", res, r.last())
	}
}

// A deleted list allows every write. The next pass writes it back, with
// the canary, and reports it.
func TestAMissingDenyListIsWrittenBackAndReported(t *testing.T) {
	r, a, _ := denyRig(t)
	if _, err := r.pass(a, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	_ = r.kube.Delete(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	if _, err := r.pass(a, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	canaryOn(t, r.list())
	if st := r.last(); st.Events["projection.deny_list_missing"] != 1 || st.Canary != applier.CanaryOK {
		t.Fatalf("status %+v", st)
	}
}

// When roid cannot be reached the pass stops at the fetch, but a missing
// list is still written back, from the last bundle applied.
func TestAMissingDenyListIsWrittenBackWhileRoidIsDown(t *testing.T) {
	r, a, _ := denyRig(t)
	if _, err := r.pass(a, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	r.roid.mu.Lock()
	r.roid.err = errors.New("connection refused")
	r.roid.mu.Unlock()
	_ = r.kube.Delete(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	res, err := r.pass(a, 2*time.Second)
	if err == nil {
		t.Fatal("a failed fetch was not an error")
	}
	canaryOn(t, r.list())
	if res.Report.Count("projection.deny_list_missing") != 1 || res.Canary != applier.CanaryOK {
		t.Fatalf("result %+v", res)
	}
	if st := r.last(); st.Events["projection.deny_list_missing"] != 1 {
		t.Fatalf("the repair was not reported: %+v", st)
	}
}
