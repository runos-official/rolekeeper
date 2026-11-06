package applier_test

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/revlog"
	"github.com/runos-official/rolekeeper/signer/token"
)

const issuerName = "https://roid.example.test"

// fakeKube is an in-memory cluster.
type fakeKube struct {
	mu   sync.Mutex
	objs map[string]kobj.Object
}

func newKube() *fakeKube { return &fakeKube{objs: map[string]kobj.Object{}} }

func (k *fakeKube) Get(_ context.Context, kind, ns, name string) (kobj.Object, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	o, ok := k.objs[kind+"/"+ns+"/"+name]
	return o.Clone(), ok, nil
}
func (k *fakeKube) Create(_ context.Context, o kobj.Object) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.objs[o.Key()] = o.Clone()
	return nil
}
func (k *fakeKube) Replace(ctx context.Context, o kobj.Object) error { return k.Create(ctx, o) }
func (k *fakeKube) Delete(_ context.Context, kind, ns, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.objs, kind+"/"+ns+"/"+name)
	return nil
}
func (k *fakeKube) ListManaged(_ context.Context, kind string) ([]kobj.Object, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []kobj.Object
	for _, o := range k.objs {
		if o.Kind == kind && o.Labels[kobj.LabelManaged] == "true" {
			out = append(out, o.Clone())
		}
	}
	return out, nil
}
func (k *fakeKube) ListRoleBindings(_ context.Context, ns string) ([]kobj.Object, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []kobj.Object
	for _, o := range k.objs {
		if o.Kind == kobj.KindRoleBinding && o.Namespace == ns {
			out = append(out, o.Clone())
		}
	}
	return out, nil
}
func (k *fakeKube) keys() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for key := range k.objs {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// fakeRoid hands out sealed bundles and records status reports.
type fakeRoid struct {
	mu      sync.Mutex
	next    []byte
	asked   [][]string
	fresh   []bool
	reports []applier.Status
	err     error // Fetch fails with it when set (roid unreachable)
}

func (f *fakeRoid) Fetch(_ context.Context, ns []string, fresh bool) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, ns)
	f.fresh = append(f.fresh, fresh)
	if f.err != nil {
		return nil, f.err
	}
	return f.next, nil
}
func (f *fakeRoid) Report(_ context.Context, s applier.Status) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, s)
	return nil
}

type rig struct {
	t      *testing.T
	now    time.Time
	issuer *token.Issuer
	trust  bundle.Trust
	kube   *fakeKube
	roid   *fakeRoid
	floor  bundle.FileFloor
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	r := &rig{t: t, now: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC), kube: newKube(), roid: &fakeRoid{},
		floor: bundle.FileFloor{Path: filepath.Join(t.TempDir(), "floor.json")}}
	log, err := revlog.Open(filepath.Join(t.TempDir(), "rev.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	rk, err := signer.NewOfflineRootBackend().CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return r.now }
	km := keys.NewManager(signer.NewSoftBackend(), log, clock)
	doc, err := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	r.issuer = &token.Issuer{Keys: km, Name: issuerName, Now: clock}
	r.trust = bundle.Trust{Issuer: issuerName, Cluster: "cl-1", RootPublicDER: rk.PublicDER, RootAlg: signer.AlgEdDSA, BundleKeys: doc}
	return r
}

func (r *rig) applier(started time.Time) *applier.Applier {
	r.t.Helper()
	v, err := bundle.NewVerifier(r.trust, func() time.Time { return r.now }, filepath.Join(r.t.TempDir(), "root-chain.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	return &applier.Applier{Verifier: v, Floor: r.floor, Roid: r.roid, Kube: r.kube,
		Namespaces: func(context.Context) ([]string, error) { return []string{"apps"}, nil },
		Now:        func() time.Time { return r.now }, Started: started}
}

func binding(person string) kobj.Object {
	return kobj.Object{Kind: kobj.KindRoleBinding, Name: "runos:view:u:" + person, Namespace: "apps",
		Labels:   map[string]string{kobj.LabelManaged: "true", kobj.LabelPolicyVersion: "pv-1", kobj.LabelAccount: "acct-a"},
		Subjects: []kobj.Subject{{Kind: "Group", Name: "runos:u:" + person + ":view", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "runos:view"}}
}

func (r *rig) offer(version uint64, objs ...kobj.Object) {
	r.t.Helper()
	raw, err := bundle.Seal(context.Background(), r.issuer, bundle.Bundle{Account: "acct-a", Cluster: "cl-1", Version: version,
		PolicyVersion: "pv-1", Namespaces: []string{"apps"}, Objects: objs, IssuedAt: r.now}, 15*time.Minute)
	if err != nil {
		r.t.Fatal(err)
	}
	r.roid.next = raw
}

func TestAGrantInTheBundleBecomesABindingAndARevokeRemovesIt(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	r.offer(1, binding("alice"))
	if res, err := a.RunOnce(context.Background()); err != nil || !res.Applied {
		t.Fatalf("v1: %+v %v", res, err)
	}
	if got := r.kube.keys(); len(got) != 1 || got[0] != "RoleBinding/apps/runos:view:u:alice" {
		t.Fatalf("cluster after v1: %v", got)
	}
	r.now = r.now.Add(time.Minute)
	r.offer(2) // alice's grant revoked
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.kube.keys(); len(got) != 0 {
		t.Fatalf("cluster after the revoke: %v", got)
	}
	if len(r.roid.reports) != 2 || r.roid.reports[1].Version != 2 || r.roid.reports[1].Error != "" {
		t.Fatalf("status reports: %+v", r.roid.reports)
	}
	if len(r.roid.asked) == 0 || len(r.roid.asked[0]) != 1 || r.roid.asked[0][0] != "apps" {
		t.Fatalf("the applier did not send its managed namespaces: %v", r.roid.asked)
	}
}

// An older bundle (a replay, or a stale roid replica) changes nothing, also
// after the applier restarts.
func TestAStaleBundleIsRefusedAndChangesNothing(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	r.offer(5, binding("alice"))
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.offer(4, binding("alice"), binding("mallory")) // the older bundle names more people
	restarted := r.applier(r.now.Add(-time.Minute))
	_, err := restarted.RunOnce(context.Background())
	if !errors.Is(err, bundle.ErrStale) {
		t.Fatalf("got %v, want ErrStale", err)
	}
	if got := r.kube.keys(); len(got) != 1 {
		t.Fatalf("a stale bundle changed the cluster: %v", got)
	}
	last := r.roid.reports[len(r.roid.reports)-1]
	if last.Error == "" || last.Version != 4 {
		t.Fatalf("the refusal was not reported: %+v", last)
	}
}

// A fresh applier (no floor yet) asks roid for a newly signed bundle and
// refuses one signed before it started, so an old captured bundle cannot
// be replayed into a new install.
func TestAFreshApplierRefusesABundleSignedBeforeItStarted(t *testing.T) {
	r := newRig(t)
	r.offer(3, binding("mallory"))
	a := r.applier(r.now.Add(time.Minute)) // started after the bundle was signed
	if _, err := a.RunOnce(context.Background()); !errors.Is(err, bundle.ErrStale) {
		t.Fatalf("got %v, want ErrStale", err)
	}
	if len(r.roid.fresh) == 0 || !r.roid.fresh[0] {
		t.Fatal("a fresh applier did not ask for a newly signed bundle")
	}
	if got := r.kube.keys(); len(got) != 0 {
		t.Fatalf("cluster changed: %v", got)
	}
}

// The applier removes only objects it owns: an unlabelled RoleBinding that
// names no runos subject stays.
func TestTheApplierPrunesOnlyWhatItOwns(t *testing.T) {
	r := newRig(t)
	foreign := kobj.Object{Kind: kobj.KindRoleBinding, Name: "team-own", Namespace: "apps",
		Subjects: []kobj.Subject{{Kind: "User", Name: "someone@example.com", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"}}
	_ = r.kube.Create(context.Background(), foreign)
	a := r.applier(r.now.Add(-time.Minute))
	r.offer(1)
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.kube.keys(); len(got) != 1 || got[0] != "RoleBinding/apps/team-own" {
		t.Fatalf("the applier removed an object it does not own: %v", got)
	}
}

// A bundle that fails the escalation lint applies nothing and does not
// raise the floor.
func TestALintFailureAppliesNothingAndKeepsTheFloor(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	bad := binding("alice")
	bad.RoleRef = &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}
	r.offer(1, bad)
	if _, err := a.RunOnce(context.Background()); err == nil {
		t.Fatal("a cluster-admin binding applied")
	}
	if got := r.kube.keys(); len(got) != 0 {
		t.Fatalf("cluster changed: %v", got)
	}
	if _, ok, _ := r.floor.Load(context.Background()); ok {
		t.Fatal("the floor moved after a refused bundle")
	}
}

// A pass that changes nothing is not reported again: the applier
// polls every few seconds, and roid's service listener has a rate limit.
// A change, a refusal or the heartbeat interval is reported.
func TestASteadyPassIsReportedOnlyOnChangeOrHeartbeat(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	a.ReportEvery = 5 * time.Minute
	r.offer(1, binding("alice"))
	for range 3 {
		if _, err := a.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.now = r.now.Add(2 * time.Second)
	}
	if len(r.roid.reports) != 1 {
		t.Fatalf("three passes of one bundle sent %d reports", len(r.roid.reports))
	}
	if r.roid.reports[0].PassMS < 0 {
		t.Fatalf("pass time %d", r.roid.reports[0].PassMS)
	}
	// A hand delete is repaired: that pass has events, so it is reported.
	_ = r.kube.Delete(context.Background(), kobj.KindRoleBinding, "apps", "runos:view:u:alice")
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.roid.reports) != 2 || r.roid.reports[1].Events["projection.drift"] != 1 {
		t.Fatalf("the repair was not reported: %+v", r.roid.reports)
	}
	r.now = r.now.Add(6 * time.Minute)
	r.offer(1, binding("alice")) // re-signed, same content
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.roid.reports) != 3 {
		t.Fatalf("no heartbeat after the interval: %d reports", len(r.roid.reports))
	}
}
