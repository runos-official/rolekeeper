package reconcile_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/reconcile"
)

const (
	pv1     = "pv-1"
	pv2     = "pv-2"
	account = "acct-a"
)

var t0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// memKube is an in-memory cluster. It keeps a log of every call, so a test
// can check the order of writes, and it can fail one named call.
type memKube struct {
	mu   sync.Mutex
	objs map[string]kobj.Object
	log  []string
	fail map[string]error // "Create", "Get", ... or "Create:Kind"
}

func newMemKube() *memKube {
	return &memKube{objs: map[string]kobj.Object{}, fail: map[string]error{}}
}

func (k *memKube) record(call, kind string) error {
	k.log = append(k.log, call+" "+kind)
	if err := k.fail[call+":"+kind]; err != nil {
		return err
	}
	return k.fail[call]
}

func (k *memKube) Get(_ context.Context, kind, ns, name string) (kobj.Object, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.record("Get", kind); err != nil {
		return kobj.Object{}, false, err
	}
	o, ok := k.objs[kind+"/"+ns+"/"+name]
	return o.Clone(), ok, nil
}

func (k *memKube) Create(_ context.Context, o kobj.Object) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.record("Create", o.Kind); err != nil {
		return err
	}
	k.objs[o.Key()] = o.Clone()
	return nil
}

// Replace overwrites the object. A Namespace merges the labels only, as the
// real client does, so the namespace itself is never rewritten.
func (k *memKube) Replace(_ context.Context, o kobj.Object) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.record("Replace", o.Kind); err != nil {
		return err
	}
	if o.Kind == kobj.KindNamespace {
		live := k.objs[o.Key()]
		if live.Labels == nil {
			live.Labels = map[string]string{}
		}
		maps.Copy(live.Labels, o.Labels)
		k.objs[o.Key()] = live
		return nil
	}
	k.objs[o.Key()] = o.Clone()
	return nil
}

func (k *memKube) Delete(_ context.Context, kind, ns, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.record("Delete", kind); err != nil {
		return err
	}
	if compile.IsKeptDenyObject(kind, name) {
		return compile.ErrDenyPolicyKept
	}
	delete(k.objs, kind+"/"+ns+"/"+name)
	return nil
}

func (k *memKube) ListManaged(_ context.Context, kind string) ([]kobj.Object, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.record("ListManaged", kind); err != nil {
		return nil, err
	}
	var out []kobj.Object
	for _, key := range slices.Sorted(maps.Keys(k.objs)) {
		o := k.objs[key]
		if o.Kind == kind && o.Labels[kobj.LabelManaged] == "true" {
			out = append(out, o.Clone())
		}
	}
	return out, nil
}

func (k *memKube) ListRoleBindings(_ context.Context, ns string) ([]kobj.Object, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.record("ListRoleBindings", ns); err != nil {
		return nil, err
	}
	var out []kobj.Object
	for _, key := range slices.Sorted(maps.Keys(k.objs)) {
		o := k.objs[key]
		if o.Kind == kobj.KindRoleBinding && o.Namespace == ns {
			out = append(out, o.Clone())
		}
	}
	return out, nil
}

// put places an object in the cluster without logging a call.
func (k *memKube) put(objs ...kobj.Object) {
	for _, o := range objs {
		k.objs[o.Key()] = o.Clone()
	}
}

func (k *memKube) has(kind, ns, name string) bool {
	_, ok := k.objs[kind+"/"+ns+"/"+name]
	return ok
}

func (k *memKube) get(kind, ns, name string) kobj.Object { return k.objs[kind+"/"+ns+"/"+name] }

// calls returns the log entries that start with the prefix, in order.
func (k *memKube) calls(prefix string) []string {
	var out []string
	for _, l := range k.log {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// writes returns the log of Create, Replace and Delete calls only.
func (k *memKube) writes() []string {
	var out []string
	for _, l := range k.log {
		for _, w := range []string{"Create ", "Replace ", "Delete "} {
			if strings.HasPrefix(l, w) {
				out = append(out, l)
			}
		}
	}
	return out
}

// sink collects events.
type sink struct{ events []reconcile.Event }

func (s *sink) Add(e reconcile.Event) { s.events = append(s.events, e) }

// rig is a reconciler with a clock that a test can move.
type rig struct {
	kube *memKube
	sink *sink
	now  time.Time
	r    *reconcile.Reconciler
}

func newRig() *rig {
	g := &rig{kube: newMemKube(), sink: &sink{}, now: t0}
	g.r = &reconcile.Reconciler{Kube: g.kube, Sink: g.sink, Now: func() time.Time { return g.now }}
	return g
}

func (g *rig) pass(out compile.Output, ns ...string) (reconcile.Report, error) {
	return g.r.Pass(context.Background(), out, ns)
}

// namespace is a managed namespace that exists in the cluster.
func namespace(name string, optIn bool) kobj.Object {
	labels := map[string]string{}
	if optIn {
		labels[kobj.LabelAccess] = "true"
	}
	return kobj.Object{Kind: kobj.KindNamespace, Name: name, Labels: labels}
}

// desiredNamespace is the namespace as the compiler labels it.
func desiredNamespace(name, pv string) kobj.Object {
	labels := map[string]string{kobj.LabelAccess: "true", kobj.LabelPolicyVersion: pv, kobj.LabelAccount: account}
	maps.Copy(labels, compile.PSALabels)
	return kobj.Object{Kind: kobj.KindNamespace, Name: name, Labels: labels}
}

func binding(ns, role, subject, pv string) kobj.Object {
	return kobj.Object{
		Kind: kobj.KindRoleBinding, Name: compile.BindingName(role, subject), Namespace: ns,
		Labels:   compile.Labels(pv, account),
		Subjects: []kobj.Subject{{Kind: "Group", Name: subject, APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: role},
	}
}

func denyObjects(t *testing.T, pv string, deny ...compile.Deny) []kobj.Object {
	t.Helper()
	objs, err := compile.DenyObjects(pv, account, deny, t0)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

// bundle is a compiled projection for one managed namespace: the five roles,
// the namespace, one group binding and the deny objects.
func bundle(t *testing.T, pv string, deny ...compile.Deny) compile.Output {
	t.Helper()
	objs := compile.FixedRoles(pv, account)
	objs = append(objs, desiredNamespace("apps", pv), binding("apps", compile.RoleView, compile.GroupSubject("ops", compile.RoleView), pv))
	objs = append(objs, denyObjects(t, pv, deny...)...)
	return compile.Output{PolicyVersion: pv, Objects: objs}
}

// seeded returns a rig whose cluster holds the managed namespace.
func seeded() *rig {
	g := newRig()
	g.kube.put(namespace("apps", true))
	return g
}

func types(rep reconcile.Report) []string {
	var out []string
	for _, e := range rep.Events {
		out = append(out, e.Type+" "+e.Object)
	}
	return out
}

func mustPass(t *testing.T, g *rig, out compile.Output) reconcile.Report {
	t.Helper()
	rep, err := g.pass(out, "apps")
	if err != nil {
		t.Fatalf("pass: %v (events %v)", err, types(rep))
	}
	return rep
}

func errBoom(what string) error { return fmt.Errorf("boom: %s", what) }
