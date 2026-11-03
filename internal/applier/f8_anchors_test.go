package applier_test

// The applier follows the root-signed
// policy-bundle key set roid serves (/v1/keysets/policy-bundle on the
// service listener), keeps it in a ConfigMap, and after a compromise
// reset refuses bundles the removed key signed, also after a restart.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/applier"
	"github.com/runos-official/rolekeeper/internal/bundle"
	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/revlog"
	"github.com/runos-official/rolekeeper/internal/signer/token"
)

// keyRoid is fakeRoid that also serves the root-signed key set.
type keyRoid struct {
	*fakeRoid
	signed string
}

func (k *keyRoid) KeySet(_ context.Context, p string) (string, error) {
	if p != string(signer.PurposePolicyBundle) {
		return "", nil
	}
	return k.signed, nil
}

func TestTheApplierFollowsAPolicyBundleKeyReset(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	// The rig's key manager, with a root this test holds.
	log, err := revlog.Open(filepath.Join(t.TempDir(), "rev2.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	off := signer.NewOfflineRootBackend()
	rk, _ := off.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
	root, _ := signer.New(ctx, off, rk.ID, signer.PurposeKeySetRoot)
	clock := func() time.Time { return r.now }
	km := keys.NewManager(signer.NewSoftBackend(), log, clock)
	doc, err := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	r.issuer = &token.Issuer{Keys: km, Name: issuerName, Now: clock}
	r.trust.RootPublicDER, r.trust.BundleKeys = rk.PublicDER, doc
	kr := &keyRoid{fakeRoid: r.roid}
	store := &applier.ConfigMapKeySets{Kube: r.kube, Namespace: "roid-k8s-applier", Name: "roid-rbac-keys"}
	mk := func() *applier.Applier {
		a := r.applier(r.now.Add(-time.Minute))
		a.Roid, a.KeySets = kr, store
		return a
	}
	a := mk()
	r.offer(1, binding("alice"))
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("v1: %+v %v", res, err)
	}
	// The thief seals a bundle with the active key before the reset.
	r.now = r.now.Add(time.Minute)
	r.offer(100, binding("alice"), binding("mallory"))
	stolen := r.roid.next
	reset, err := km.Compromise(ctx, signer.PurposePolicyBundle, doc.Active().Kid, root)
	if err != nil {
		t.Fatal(err)
	}
	kr.signed = reset
	r.roid.next = stolen
	if _, err := a.RunOnce(ctx); err == nil {
		t.Fatal("after the reset the applier applied a bundle the removed key signed")
	}
	if _, ok, _ := r.kube.Get(ctx, "RoleBinding", "apps", "runos:view:u:mallory"); ok {
		t.Fatalf("the stolen bundle changed the cluster: %v", r.kube.keys())
	}
	r.now = r.now.Add(time.Minute)
	r.offer(3, binding("alice"))
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("a bundle from the new key: %+v %v", res, err)
	}
	// A restart with the install pin keeps the reset, from the ConfigMap,
	// even when roid is not reachable for the key set.
	kr.signed = ""
	re := mk()
	r.roid.next = stolen
	if _, err := re.RunOnce(ctx); err == nil {
		t.Fatal("after a restart the removed key is trusted again")
	}
	_ = bundle.ErrStale
}
