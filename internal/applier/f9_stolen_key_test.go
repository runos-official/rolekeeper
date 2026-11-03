package applier_test

// A stolen key and the Kubernetes applier: the
// policy-bundle key set is root-signed, so a stolen policy-bundle key
// neither makes a key set the applier follows nor holds off the root's
// reset: after the stolen key's set was offered, the reset still applies
// and the stolen key's bundle is refused.

import (
	"context"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/signer"
)

func TestF9AStolenPolicyBundleKeyNeitherForgesAKeySetNorVetoesTheReset(t *testing.T) {
	ctx := context.Background()
	r := newR9Rig(t)
	a := r.mk()
	r.offer(1, binding("alice"))
	if res, err := a.RunOnce(ctx); err != nil || !res.Applied {
		t.Fatalf("fixture: v1: %+v %v", res, err)
	}
	// The thief holds the active key and offers a key set it signed.
	forged, err := r.km.LegacyLeafSignedDoc(ctx, signer.PurposePolicyBundle)
	if err != nil {
		t.Fatal(err)
	}
	r.kr.signed = forged
	r.now = r.now.Add(time.Minute)
	if _, err := a.RunOnce(ctx); err == nil {
		t.Log("the pass reports nothing for the refused key set")
	}
	if stored, _, _ := r.store.inner.Load(ctx); stored == forged {
		t.Fatal("the applier kept a key set the stolen key signed")
	}
	// The root's reset after it.
	r.offer(100, binding("alice"), binding("mallory"))
	r.stolen = r.roid.next
	reset, err := r.km.Compromise(ctx, signer.PurposePolicyBundle, r.doc.Active().Kid, r.root)
	if err != nil {
		t.Fatal(err)
	}
	r.kr.signed = reset
	r.now = r.now.Add(time.Minute)
	if _, err := a.RunOnce(ctx); err == nil && r.malloryBound() {
		t.Fatal("after the root's reset the applier applied a bundle the removed key signed")
	}
	if stored, _, _ := r.store.inner.Load(ctx); stored != reset {
		t.Fatalf("the root's reset was not taken after the stolen key's set (stored %d bytes)", len(stored))
	}
}
