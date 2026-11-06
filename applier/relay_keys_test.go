package applier_test

// 3.6: the key set travels in the relay ConfigMap. The transport cannot add,
// remove or roll back a key: the pinned root signs every set.

import (
	"context"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/signer"
)

func TestRelayKeySetResetThroughTheConfigMapRemovesAKeyAndForgeriesAreIgnored(t *testing.T) {
	ctx := context.Background()
	r9 := newR9Rig(t)
	r := &relayRig{rig: r9.rig, rk: newRelayKube(), labelled: []string{"apps"}}
	a := r.mk(t)
	a.KeySets = applier.ConfigMapKeySets{Kube: r.rk, Namespace: relayNS, Name: "roid-rbac-keys"}
	_ = r.floor.Store(ctx, floorOf(0))
	r.publish(t, 1, "alice")
	mustPass(t, a)

	// The thief signs a bundle with the active key K.
	r.now = r.now.Add(time.Minute)
	stolen := r.envelope(t, bundle.Bundle{Version: 100, Namespaces: []string{"apps"}, Objects: append(denyObjs(t, r.now), binding("alice"), binding("mallory"))})

	// A key set the thief signed (not the root) is ignored.
	forged, err := r9.km.LegacyLeafSignedDoc(ctx, signer.PurposePolicyBundle)
	if err != nil {
		t.Fatal(err)
	}
	r.setRelay(forged, "")
	reset, err := r9.km.Compromise(ctx, signer.PurposePolicyBundle, r9.doc.Active().Kid, r9.root)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.RunOnce(ctx)
	if stored, _, _ := a.KeySets.Load(ctx); stored == forged {
		t.Fatal("the applier kept a key set the stolen key signed")
	}

	// The root's reset, through the relay ConfigMap.
	r.setRelay(reset, "")
	r.now = r.now.Add(time.Minute)
	r.write(t, stolen, "")
	if res, err := a.RunOnce(ctx); err == nil && res.Applied || r.bound("mallory") {
		t.Fatalf("a bundle the removed key signed applied: %+v %v", res, err)
	}
	if stored, _, _ := a.KeySets.Load(ctx); stored != reset {
		t.Fatalf("the reset was not taken (stored %d bytes)", len(stored))
	}

	// The forged set, offered again, does not roll the reset back.
	r.setRelay(forged, "")
	r.write(t, stolen, "")
	_, _ = a.RunOnce(ctx)
	if stored, _, _ := a.KeySets.Load(ctx); stored != reset {
		t.Fatal("the transport rolled a key set back")
	}
	if r.bound("mallory") {
		t.Fatal("mallory bound")
	}
}
