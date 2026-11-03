package applier_test

// When an account closes or a cluster leaves an account, roid hands
// the cluster's applier one signed retire bundle. The applier removes every
// object it manages, reports, and stops. A local fail-safe removes them
// too when roid keeps refusing the applier past a bound; an unreachable
// roid never counts.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/applier"
	"github.com/runos-official/rolekeeper/internal/bundle"
	"github.com/runos-official/rolekeeper/internal/compile"
	"github.com/runos-official/rolekeeper/internal/kobj"
)

// managedCRB is a managed ClusterRoleBinding (cluster-wide grant).
func managedCRB(person string) kobj.Object {
	return kobj.Object{Kind: kobj.KindClusterRoleBinding, Name: "runos:view:cw:" + person,
		Labels:   map[string]string{kobj.LabelManaged: "true", kobj.LabelPolicyVersion: "pv-1", kobj.LabelAccount: "acct-a"},
		Subjects: []kobj.Subject{{Kind: "Group", Name: "runos:cw:view", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "runos:view"}}
}

// denyUntil is fixed, so the same bundle content can be offered again.
var denyUntil = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

func denyObjs(t *testing.T, now time.Time) []kobj.Object {
	t.Helper()
	objs, err := compile.DenyObjects("pv-2", "acct-a", []compile.Deny{{Person: "alice", Until: denyUntil}}, now)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func (r *rig) offerRetire(version uint64, objs ...kobj.Object) {
	r.t.Helper()
	raw, err := bundle.Seal(context.Background(), r.issuer, bundle.Bundle{Account: "acct-a", Cluster: "cl-1", Version: version,
		PolicyVersion: "pv-2", Namespaces: []string{"apps"}, Objects: objs, Retire: true, IssuedAt: r.now}, 15*time.Minute)
	if err != nil {
		r.t.Fatal(err)
	}
	r.roid.next = raw
}

func (r *rig) setErr(err error) {
	r.roid.mu.Lock()
	r.roid.err = err
	r.roid.mu.Unlock()
}

func (r *rig) fetches() int {
	r.roid.mu.Lock()
	defer r.roid.mu.Unlock()
	return len(r.roid.asked)
}

// seed applies v1 with a person binding and a cluster-wide binding, and
// puts a team's own binding and a hand-made runos binding next to them.
func seed(t *testing.T, r *rig, a *applier.Applier) {
	t.Helper()
	ctx := context.Background()
	team := kobj.Object{Kind: kobj.KindRoleBinding, Name: "team-own", Namespace: "apps",
		Subjects: []kobj.Subject{{Kind: "User", Name: "someone@example.com", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"}}
	_ = r.kube.Create(ctx, team)
	objs := append(denyObjs(t, r.now), binding("alice"))
	r.offer(1, objs...)
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("v1: %+v %v", res, err)
	}
	hand := kobj.Object{Kind: kobj.KindRoleBinding, Name: "hand-made", Namespace: "apps",
		Subjects: []kobj.Subject{{Kind: "Group", Name: "runos:u:bob:edit", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "edit"}}
	_ = r.kube.Create(ctx, hand)
	// Left by an older roid, or by hand with the label: managed, so the
	// applier owns it and a retire takes it.
	_ = r.kube.Create(ctx, managedCRB("alice"))
}

// what the cluster must hold once the applier has let go: the team's own
// binding and the deny objects, nothing else.
func wantUnbound(t *testing.T, r *rig) {
	t.Helper()
	got := strings.Join(r.kube.keys(), " ")
	for _, gone := range []string{"runos:view:u:alice", "runos:view:cw:alice", "hand-made"} {
		if strings.Contains(got, gone) {
			t.Fatalf("%s is still on the cluster: %s", gone, got)
		}
	}
	for _, kept := range []string{"RoleBinding/apps/team-own", "ConfigMap/" + compile.DenyNamespace + "/" + compile.DenyPolicyName} {
		if !strings.Contains(got, kept) {
			t.Fatalf("%s was removed: %s", kept, got)
		}
	}
}

func TestX11ARetireBundleRemovesEveryManagedBindingReportsAndStops(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	a.RetiredEvery = 10 * time.Minute
	seed(t, r, a)

	r.now = r.now.Add(time.Minute)
	r.offerRetire(2, denyObjs(t, r.now)...)
	res, err := a.RunOnce(context.Background())
	if err != nil || !res.Applied || !res.Retired {
		t.Fatalf("retire: %+v %v", res, err)
	}
	wantUnbound(t, r)
	last := r.roid.reports[len(r.roid.reports)-1]
	if !last.Retired || !last.Applied || last.Version != 2 || last.Error != "" {
		t.Fatalf("the retire was not reported: %+v", last)
	}
	f, ok, _ := r.floor.Load(context.Background())
	if !ok || !f.Retired || f.Version != 2 {
		t.Fatalf("floor after the retire: %+v ok=%v", f, ok)
	}

	// Stopped: no fetch, no report and no write until the retired poll.
	n, reports := r.fetches(), len(r.roid.reports)
	r.now = r.now.Add(2 * time.Second)
	_ = r.kube.Create(context.Background(), binding("carol")) // a binding that appears later is not this applier's business now
	if res, err := a.RunOnce(context.Background()); err != nil || !res.Retired {
		t.Fatalf("pass after the retire: %+v %v", res, err)
	}
	if r.fetches() != n || len(r.roid.reports) != reports {
		t.Fatalf("a retired applier fetched or reported: fetches %d->%d reports %d->%d", n, r.fetches(), reports, len(r.roid.reports))
	}

	// A restart keeps it retired; roid's refusal changes nothing.
	r.setErr(fmt.Errorf("%w: k8s.not_allowed retired", applier.ErrRoidRefused))
	again := r.applier(r.now.Add(-time.Minute))
	if res, err := again.RunOnce(context.Background()); !res.Retired || err != nil {
		t.Fatalf("restarted retired applier: %+v %v", res, err)
	}
	if len(r.roid.reports) != reports {
		t.Fatalf("a restarted retired applier reported: %+v", r.roid.reports[reports:])
	}
}

// A retire bundle is a pure reduction: one that carries anything beyond
// the deny list is refused whole, and nothing is removed or added.
func TestX11ARetireBundleThatCarriesAGrantIsRefused(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	seed(t, r, a)
	before := r.kube.keys()
	r.now = r.now.Add(time.Minute)
	r.offerRetire(2, append(denyObjs(t, r.now), binding("mallory"))...)
	res, err := a.RunOnce(context.Background())
	if err == nil || res.Retired || !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("a retire bundle with a grant: %+v %v", res, err)
	}
	if got := r.kube.keys(); strings.Join(got, " ") != strings.Join(before, " ") {
		t.Fatalf("the cluster changed: %v -> %v", before, got)
	}
	if f, _, _ := r.floor.Load(context.Background()); f.Version != 1 || f.Retired {
		t.Fatalf("floor moved: %+v", f)
	}
}

// A retired applier polls slowly. A newer signed bundle (the cluster was
// added to the account again) brings it back; a stale one does not.
func TestX11ANewerBundleResumesARetiredApplier(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	a.RetiredEvery = 10 * time.Minute
	seed(t, r, a)
	r.offerRetire(2, denyObjs(t, r.now)...)
	if res, _ := a.RunOnce(context.Background()); !res.Retired {
		t.Fatal("not retired")
	}
	r.offer(1, binding("alice")) // the old v1 again: below the floor
	r.now = r.now.Add(11 * time.Minute)
	if res, err := a.RunOnce(context.Background()); !errors.Is(err, bundle.ErrStale) || !res.Retired {
		t.Fatalf("stale bundle on a retired applier: %+v %v", res, err)
	}
	r.offer(3, append(denyObjs(t, r.now), binding("bob"))...)
	r.now = r.now.Add(11 * time.Minute)
	res, err := a.RunOnce(context.Background())
	if err != nil || res.Retired || !res.Applied {
		t.Fatalf("v3 on a retired applier: %+v %v", res, err)
	}
	if !strings.Contains(strings.Join(r.kube.keys(), " "), "runos:view:u:bob") {
		t.Fatalf("v3 not applied: %v", r.kube.keys())
	}
	if f, _, _ := r.floor.Load(context.Background()); f.Retired || f.Version != 3 {
		t.Fatalf("floor after the resume: %+v", f)
	}
}

// Fail-safe: roid refused the applier (an authenticated 403) on every pass
// for longer than the bound, so the applier removes what it manages.
func TestX11RefusedForLongerThanTheBoundTheApplierUnbindsItself(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	a.RefusedBound = time.Hour
	seed(t, r, a)
	r.setErr(fmt.Errorf("%w: k8s.not_allowed cluster", applier.ErrRoidRefused))
	for _, step := range []time.Duration{time.Minute, 30 * time.Minute, 29 * time.Minute} {
		r.now = r.now.Add(step)
		if res, _ := a.RunOnce(context.Background()); res.FailSafe || res.Retired {
			t.Fatalf("fail-safe fired early: %+v", res)
		}
	}
	if !strings.Contains(strings.Join(r.kube.keys(), " "), "runos:view:u:alice") {
		t.Fatal("binding removed inside the bound")
	}
	r.now = r.now.Add(2 * time.Minute) // 62 minutes after the first refusal
	res, _ := a.RunOnce(context.Background())
	if !res.FailSafe || !res.Retired {
		t.Fatalf("fail-safe did not fire: %+v", res)
	}
	wantUnbound(t, r)
	if f, ok, _ := r.floor.Load(context.Background()); !ok || !f.Retired || f.Version != 1 {
		t.Fatalf("floor after the fail-safe: %+v", f)
	}
	// The same bundle served again (roid answers for the cluster after
	// all) brings the access back: the fail-safe never burns the floor.
	r.setErr(nil)
	r.now = r.now.Add(time.Hour)
	r.offer(1, append(denyObjs(t, r.now), binding("alice"))...)
	if res, err := a.RunOnce(context.Background()); err != nil || res.Retired {
		t.Fatalf("resume after the fail-safe: %+v %v", res, err)
	}
	if !strings.Contains(strings.Join(r.kube.keys(), " "), "runos:view:u:alice") {
		t.Fatalf("access not back after roid answered again: %v", r.kube.keys())
	}
}

// An outage is not a refusal: roid unreachable, 5xx, 429 or 401 for two
// days removes nothing. A success in between restarts the clock.
func TestX11AnUnreachableRoidNeverUnbinds(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	a.RefusedBound = time.Hour
	seed(t, r, a)
	r.setErr(errors.New("dial tcp 192.0.2.10:8443: connection refused"))
	for range 48 {
		r.now = r.now.Add(time.Hour)
		if res, _ := a.RunOnce(context.Background()); res.FailSafe || res.Retired {
			t.Fatalf("an outage fired the fail-safe: %+v", res)
		}
	}
	// One refusal, then an outage, then a success, then refusals inside
	// the bound measured from the success.
	r.setErr(fmt.Errorf("%w: k8s.not_allowed", applier.ErrRoidRefused))
	r.now = r.now.Add(time.Minute)
	_, _ = a.RunOnce(context.Background())
	r.setErr(nil)
	r.now = r.now.Add(50 * time.Minute)
	r.offer(1, append(denyObjs(t, r.now), binding("alice"))...)
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.setErr(fmt.Errorf("%w: k8s.not_allowed", applier.ErrRoidRefused))
	for range 5 {
		r.now = r.now.Add(10 * time.Minute)
		if res, _ := a.RunOnce(context.Background()); res.FailSafe {
			t.Fatalf("the success did not restart the clock: %+v", res)
		}
	}
	if !strings.Contains(strings.Join(r.kube.keys(), " "), "runos:view:u:alice") {
		t.Fatal("binding removed")
	}
}

// The default bound is long (a day): a short run of refusals never fires.
func TestX11TheDefaultFailSafeBoundIsADay(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	seed(t, r, a)
	r.setErr(fmt.Errorf("%w: k8s.not_allowed", applier.ErrRoidRefused))
	for range 23 {
		r.now = r.now.Add(time.Hour)
		if res, _ := a.RunOnce(context.Background()); res.FailSafe {
			t.Fatalf("fired after %s", 23*time.Hour)
		}
	}
	r.now = r.now.Add(2 * time.Hour)
	if res, _ := a.RunOnce(context.Background()); !res.FailSafe {
		t.Fatalf("did not fire after 25 h: %+v", res)
	}
}

// The HTTP client tells roid's refusal (403 k8s.not_allowed) from every
// other answer: only that one is ErrRoidRefused.
func TestX11HTTPRoidClassesOnlyA403NotAllowedAsARefusal(t *testing.T) {
	dir := t.TempDir()
	_, certFile, keyFile, clientPool, _ := certs(t, dir, "applier")
	serverCA, _, _, _, serverLeaf := certs(t, t.TempDir(), "localhost")
	answer := func(w http.ResponseWriter) {}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { answer(w) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverLeaf}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool}
	srv.StartTLS()
	defer srv.Close()
	caFile := filepath.Join(dir, "roid-ca.pem")
	_ = os.WriteFile(caFile, serverCA, 0o600)
	c := &applier.HTTPRoid{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Account: "acct-a",
		CertFile: certFile, KeyFile: keyFile, CAFile: caFile}
	for _, tc := range []struct {
		status  int
		body    string
		refused bool
	}{
		{403, `{"error":{"code":"k8s.not_allowed","reason":"cluster"}}`, true},
		{403, `{"error":{"code":"k8s.not_allowed","reason":"retired"}}`, true},
		{403, `{"error":{"code":"forbidden"}}`, false},
		{401, `{"error":{"code":"k8s.unauthenticated"}}`, false},
		{503, `{"error":{"code":"k8s.unavailable"}}`, false},
		{429, `{"error":{"code":"rate_limited"}}`, false},
		{502, `bad gateway`, false},
	} {
		answer = func(w http.ResponseWriter) { w.WriteHeader(tc.status); _, _ = w.Write([]byte(tc.body)) }
		_, err := c.Fetch(context.Background(), []string{"apps"}, false)
		if err == nil || errors.Is(err, applier.ErrRoidRefused) != tc.refused {
			t.Fatalf("%d %s: err %v, refused want %v", tc.status, tc.body, err, tc.refused)
		}
	}
	srv.Close()
	if _, err := c.Fetch(context.Background(), []string{"apps"}, false); err == nil || errors.Is(err, applier.ErrRoidRefused) {
		t.Fatalf("a closed server: %v", err)
	}
}

// The ConfigMap floor keeps the retired mark across a restart.
func TestX11ConfigMapFloorKeepsTheRetiredMark(t *testing.T) {
	ex := &memCM{}
	f := applier.ConfigMapFloor{Kube: ex, Namespace: "roid-applier", Name: "roid-rbac-floor"}
	if err := f.Store(context.Background(), bundle.Floor{Version: 4, Digest: "d4", Retired: true}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := f.Load(context.Background())
	if err != nil || !ok || !got.Retired || got.Version != 4 {
		t.Fatalf("after restart: %+v ok=%v err=%v", got, ok, err)
	}
	_ = f.Store(context.Background(), bundle.Floor{Version: 5, Digest: "d5"})
	if got, _, _ := f.Load(context.Background()); got.Retired {
		t.Fatalf("resumed floor still retired: %+v", got)
	}
}
