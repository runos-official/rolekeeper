package applier_test

// Review 9 (anchors): the applier follows the root-signed policy-bundle
// key set and keeps it in the roid-rbac-keys ConfigMap. These tests check
// that the ConfigMap really holds the newest set the applier trusts, and
// that a key-set store it cannot read fails the pass the way an
// unreadable floor does, so a restart never verifies with an install pin
// that still holds a key a compromise reset removed.

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/revlog"
	"github.com/runos-official/rolekeeper/signer/token"
)

// r9KeyRoid serves the key set, or fails like an unreachable route.
type r9KeyRoid struct {
	*fakeRoid
	mu     sync.Mutex
	signed string
	down   bool
}

func (k *r9KeyRoid) KeySet(_ context.Context, p string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return "", errors.New("key set route unreachable")
	}
	if p != string(signer.PurposePolicyBundle) {
		return "", nil
	}
	return k.signed, nil
}

// r9Store is ConfigMapKeySets whose Load and Store can fail on demand.
type r9Store struct {
	inner     applier.ConfigMapKeySets
	failLoad  bool
	failStore bool
}

func (s *r9Store) Load(ctx context.Context) (string, bool, error) {
	if s.failLoad {
		return "", false, errors.New("configmap read: connection refused")
	}
	return s.inner.Load(ctx)
}

func (s *r9Store) Store(ctx context.Context, signed string) error {
	if s.failStore {
		return errors.New("configmap write: connection refused")
	}
	return s.inner.Store(ctx, signed)
}

// r9Rig is the rig with a root this test holds and a reset of the active
// policy-bundle key K, applied by a running applier.
type r9Rig struct {
	*rig
	km     *keys.Manager
	root   *signer.Signer
	doc    keys.Doc
	kr     *r9KeyRoid
	store  *r9Store
	stolen []byte
}

func newR9Rig(t *testing.T) *r9Rig {
	t.Helper()
	ctx := context.Background()
	r := newRig(t)
	log, err := revlog.Open(filepath.Join(t.TempDir(), "rev-r9.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	off := signer.NewOfflineRootBackend()
	rk, err := off.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	root, err := signer.New(ctx, off, rk.ID, signer.PurposeKeySetRoot)
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
	r.trust.RootPublicDER, r.trust.BundleKeys = rk.PublicDER, doc
	return &r9Rig{rig: r, km: km, root: root, doc: doc,
		kr:    &r9KeyRoid{fakeRoid: r.roid},
		store: &r9Store{inner: applier.ConfigMapKeySets{Kube: r.kube, Namespace: "roid-k8s-applier", Name: "roid-rbac-keys"}}}
}

func (r *r9Rig) mk() *applier.Applier {
	a := r.applier(r.now.Add(-time.Minute))
	a.Roid, a.KeySets = r.kr, r.store
	return a
}

// resetK applies v1 with the install pin, has the thief seal a bundle with
// the active key K, then installs the root-signed reset that removes K.
func (r *r9Rig) resetK(t *testing.T, a *applier.Applier) {
	t.Helper()
	ctx := context.Background()
	r.offer(1, binding("alice"))
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("fixture: v1: %+v %v", res, err)
	}
	r.now = r.now.Add(time.Minute)
	r.offer(100, binding("alice"), binding("mallory"))
	r.stolen = r.roid.next
	reset, err := r.km.Compromise(ctx, signer.PurposePolicyBundle, r.doc.Active().Kid, r.root)
	if err != nil {
		t.Fatal(err)
	}
	r.kr.signed = reset
}

func (r *r9Rig) malloryBound() bool {
	_, ok, _ := r.kube.Get(context.Background(), kobj.KindRoleBinding, "apps", "runos:view:u:mallory")
	return ok
}

// A failed ConfigMap write after the applier took the reset is never
// written again: the next passes see the same set (no change) and skip the
// store. The ConfigMap then keeps the older set for good, and a restart
// while the key-set route is unreachable trusts K again.
func TestApplierRetriesTheKeySetStoreAfterAFailedWrite(t *testing.T) {
	ctx := context.Background()
	r := newR9Rig(t)
	a := r.mk()
	r.resetK(t, a)

	// The pass that takes the reset cannot write the ConfigMap.
	r.store.failStore = true
	r.now = r.now.Add(time.Minute)
	r.offer(2, binding("alice"))
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("fixture: v2 from the new key: %+v %v", res, err)
	}
	// The API server is back; several healthy passes follow.
	r.store.failStore = false
	for i := 0; i < 3; i++ {
		r.now = r.now.Add(time.Second)
		if _, err := a.RunOnce(ctx); err != nil {
			t.Fatalf("fixture: steady pass %d: %v", i, err)
		}
	}
	stored, _, _ := r.store.inner.Load(ctx)
	if stored != r.kr.signed {
		t.Errorf("defect: after the API server recovered and 3 more passes, the roid-rbac-keys ConfigMap does not hold the reset the applier trusts (stored %d bytes, want the reset): a failed key-set store is never retried", len(stored))
	}

	// Restart while /v1/keysets is unreachable; a bundle K signed arrives.
	r.kr.down = true
	re := r.mk()
	r.roid.next = r.stolen
	res, err := re.RunOnce(ctx)
	if err == nil && res.Applied || r.malloryBound() {
		t.Fatalf("defect: after a restart the applier applied v%d, a bundle signed by the policy-bundle key that a root-signed compromise reset removed (the ConfigMap kept the pre-reset set after one failed write)", res.Version)
	}
}

// An unreadable key-set ConfigMap at start lets the pass verify with the
// install pin, which still holds K. An unreadable floor fails the pass
// ("floor unreadable"); an unreadable key set must too.
func TestApplierFailsThePassWhenTheKeySetStoreIsUnreadable(t *testing.T) {
	ctx := context.Background()
	r := newR9Rig(t)
	a := r.mk()
	r.resetK(t, a)
	r.now = r.now.Add(time.Minute)
	r.offer(2, binding("alice"))
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("fixture: v2 from the new key: %+v %v", res, err)
	}
	if stored, _, _ := r.store.inner.Load(ctx); stored != r.kr.signed {
		t.Fatal("fixture: the reset is not in the ConfigMap")
	}

	// Restart: the ConfigMap read fails once and roid's key-set route is
	// unreachable. A bundle K signed arrives.
	r.store.failLoad = true
	r.kr.down = true
	re := r.mk()
	r.roid.next = r.stolen
	res, err := re.RunOnce(ctx)
	if err == nil && res.Applied || r.malloryBound() {
		t.Fatalf("defect: with the roid-rbac-keys ConfigMap unreadable at start, the applier verified with the install pin and applied v%d, a bundle signed by the policy-bundle key a root-signed reset removed (it should fail the pass, as it does for an unreadable floor)", res.Version)
	}
}
