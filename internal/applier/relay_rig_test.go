package applier_test

// The relay rig: the applier reads its bundle, key set and refusal from
// ConfigMaps in a fake API server and writes its status there. The roid
// side is the test issuer; the conductor side is these helpers, which do
// what conductor does: split the envelope, gzip the body, write the
// objects.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/internal/applier"
	"github.com/runos-official/rolekeeper/internal/bundle"
	"github.com/runos-official/rolekeeper/internal/kobj"
	"github.com/runos-official/rolekeeper/internal/kubeapi"
	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/token"
)

const relayNS = "roid-k8s-applier"

// relayKube is the fake API server for the relay ConfigMaps. Every write
// moves the resourceVersion, as the real one does.
type relayKube struct {
	mu        sync.Mutex
	cms       map[string]kobj.Object
	rv        int
	gets      map[string]int
	metas     int
	failGet   map[string]error
	failApply error
}

func newRelayKube() *relayKube {
	return &relayKube{cms: map[string]kobj.Object{}, gets: map[string]int{}, failGet: map[string]error{}}
}

func (k *relayKube) put(name string, data map[string]string, bin map[string][]byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rv++
	k.cms[name] = kobj.Object{Kind: kobj.KindConfigMap, Namespace: relayNS, Name: name, Data: data, BinaryData: bin, ResourceVersion: itoa(k.rv)}
}

func (k *relayKube) drop(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.cms, name)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func (k *relayKube) Get(_ context.Context, kind, ns, name string) (kobj.Object, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if ns != relayNS || kind != kobj.KindConfigMap {
		return kobj.Object{}, false, nil
	}
	k.gets[name]++
	if err := k.failGet[name]; err != nil {
		return kobj.Object{}, false, err
	}
	o, ok := k.cms[name]
	return o.Clone(), ok, nil
}

func (k *relayKube) Metadata(_ context.Context, kind, ns, name string) (kubeapi.Meta, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.metas++
	if err := k.failGet[name]; err != nil {
		return kubeapi.Meta{}, false, err
	}
	o, ok := k.cms[name]
	return kubeapi.Meta{ResourceVersion: o.ResourceVersion}, ok, nil
}

// Create is a server-side apply of the whole object.
func (k *relayKube) Create(_ context.Context, o kobj.Object) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failApply != nil {
		return k.failApply
	}
	k.rv++
	o = o.Clone()
	o.ResourceVersion = itoa(k.rv)
	k.cms[o.Name] = o
	return nil
}

func (k *relayKube) getCount(name string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.gets[name]
}

type relayRig struct {
	*rig
	rk       *relayKube
	skew     time.Duration // the applier node's clock minus roid's clock
	labelled []string      // the namespaces the cluster labels as managed
	trustSum string
}

// newBareRelayRig is a cluster whose applier never applied anything: no
// floor, so the first bundle needs a fresh token.
func newBareRelayRig(t *testing.T) *relayRig {
	t.Helper()
	return &relayRig{rig: newRig(t), rk: newRelayKube(), labelled: []string{"apps"}, trustSum: "cc" + hex.EncodeToString(make([]byte, 31))}
}

// newRelayRig is a cluster whose applier already holds a floor (version 0),
// so a test about something else does not need the fresh-start dance.
func newRelayRig(t *testing.T) *relayRig {
	t.Helper()
	r := newBareRelayRig(t)
	if err := r.floor.Store(context.Background(), bundle.Floor{Version: 0, Digest: "seed"}); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *relayRig) clock() time.Time { return r.now.Add(r.skew) }

type relayApplier struct {
	*applier.Applier
	cm *applier.ConfigMapRoid
}

// mk builds a new applier process: new verifier, new status counter, same
// cluster, same floor.
func (r *relayRig) mk(t *testing.T) *relayApplier {
	t.Helper()
	v, err := bundle.NewVerifier(r.trust, r.clock, filepath.Join(t.TempDir(), "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	v.ExpectAccount("acct-a")
	started := r.clock()
	cm := &applier.ConfigMapRoid{Kube: r.rk, Verifier: v, Namespace: relayNS, Account: "acct-a", Cluster: "cl-1",
		TrustSHA256: r.trustSum, Version: "1.3.0-test", Started: started, Now: r.clock}
	a := &applier.Applier{Verifier: v, Floor: r.floor, Roid: cm, Kube: r.kube,
		Namespaces: func(context.Context) ([]string, error) { return append([]string(nil), r.labelled...), nil },
		Now:        r.clock, Started: started, ReportEvery: 60 * time.Second}
	return &relayApplier{Applier: a, cm: cm}
}

// envelope seals a bundle at roid's clock.
func (r *relayRig) envelope(t *testing.T, b bundle.Bundle) []byte {
	t.Helper()
	if b.Account == "" {
		b.Account = "acct-a"
	}
	if b.Cluster == "" {
		b.Cluster = "cl-1"
	}
	if b.PolicyVersion == "" {
		b.PolicyVersion = "pv-1"
	}
	b.IssuedAt = r.now
	raw, err := bundle.Seal(context.Background(), r.issuer, b, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func gzipOf(t *testing.T, body []byte) []byte {
	t.Helper()
	gz, err := bundle.GzipBody(body)
	if err != nil {
		t.Fatal(err)
	}
	return gz
}

// write is conductor's write: token and body.gz in the bundle ConfigMap,
// and the fresh token when there is one.
func (r *relayRig) write(t *testing.T, raw []byte, fresh string) {
	t.Helper()
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	data := map[string]string{"token": env.Bundle}
	if fresh != "" {
		data["fresh"] = fresh
	}
	r.rk.put("roid-rbac-bundle", data, map[string][]byte{"body.gz": gzipOf(t, env.Body)})
}

// publish seals and writes the usual bundle: the deny list, a binding for
// each person, the labelled namespaces.
func (r *relayRig) publish(t *testing.T, version uint64, people ...string) []byte {
	t.Helper()
	objs := denyObjs(t, r.now)
	for _, p := range people {
		objs = append(objs, binding(p))
	}
	raw := r.envelope(t, bundle.Bundle{Version: version, Namespaces: append([]string(nil), r.labelled...), Objects: objs})
	r.write(t, raw, "")
	return raw
}

func (r *relayRig) mint(t *testing.T, cls, sub, acct, cluster, jti string) string {
	t.Helper()
	tok, err := r.issuer.Issue(context.Background(), signer.PurposePolicyBundle, token.Claims{
		Claims: jwt.Claims{Subject: sub, ID: jti, Audience: jwt.Audience{bundle.Audience(cluster)}}, Class: cls, Account: acct}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (r *relayRig) freshFor(t *testing.T, nonce string, raw []byte) string {
	t.Helper()
	probe, err := bundle.NewVerifier(r.trust, func() time.Time { return r.now }, filepath.Join(t.TempDir(), "p.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := probe.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "acct-a", "cl-1", bundle.FreshTokenID(nonce, v.Digest))
}

func (r *relayRig) refusal(t *testing.T, reason string) string {
	return r.mint(t, "k8s-rbac-refusal", "k8s-rbac-refusal:"+reason, "acct-a", "cl-1", "")
}

// setRelay writes the relay ConfigMap (key set and refusal).
func (r *relayRig) setRelay(keyset, refusal string) {
	data := map[string]string{}
	if keyset != "" {
		data["keyset.policy-bundle"] = keyset
	}
	if refusal != "" {
		data["refusal.jwt"] = refusal
	}
	r.rk.put("roid-rbac-relay", data, nil)
}

func (r *relayRig) status(t *testing.T) applier.RelayStatus {
	t.Helper()
	cm, ok, _ := r.rk.Get(context.Background(), kobj.KindConfigMap, relayNS, "roid-rbac-status")
	if !ok {
		t.Fatal("the applier wrote no status ConfigMap")
	}
	var st applier.RelayStatus
	if err := json.Unmarshal([]byte(cm.Data["status.json"]), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func (r *relayRig) bound(person string) bool {
	_, ok, _ := r.kube.Get(context.Background(), kobj.KindRoleBinding, "apps", "runos:view:u:"+person)
	return ok
}

func (r *relayRig) floorVersion() uint64 {
	f, _, _ := r.floor.Load(context.Background())
	return f.Version
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func mustPass(t *testing.T, a *relayApplier) applier.Result {
	t.Helper()
	res, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("pass: %v (%+v)", err, res)
	}
	return res
}

var _ = errors.New
var _ = bytes.Equal

var errTest = errors.New("connection refused")

func floorOf(v uint64) bundle.Floor { return bundle.Floor{Version: v, Digest: "none"} }
