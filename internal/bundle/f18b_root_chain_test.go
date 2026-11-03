package bundle_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/bundle"
	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/revlog"
	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
)

// The applier's trust file carries the root chain (root_chain).
func TestBundleKeySetsFollowTheRootChain(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	log, err := revlog.Open(filepath.Join(t.TempDir(), "revocations.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	root := func() *signer.Signer {
		off := signer.NewOfflineRootBackend()
		k, _ := off.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
		s, _ := signer.New(ctx, off, k.ID, signer.PurposeKeySetRoot)
		return s
	}
	oldRoot, newRoot := root(), root()
	km := keys.NewManager(signer.NewSoftBackend(), log, clock)
	doc, err := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	link, _ := roottrust.HandoverBundle(oldRoot, newRoot, 1, now.Add(time.Minute), time.Hour) // Old-root sets below predate it
	ch, _ := roottrust.EncodeChain([][]byte{link})
	trust := bundle.Trust{Issuer: issuerName, Cluster: "cl-1", RootPublicDER: oldRoot.Info().PublicDER, RootAlg: signer.AlgEdDSA, BundleKeys: doc, RootChain: ch}
	v, err := bundle.NewVerifier(trust, clock, filepath.Join(t.TempDir(), "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	publish := func(by *signer.Signer) string {
		s, err := km.Publish(ctx, signer.PurposePolicyBundle, by)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if err := v.UpdateKeys(publish(oldRoot)); err != nil {
		t.Fatalf("the old root inside the overlap: %v", err)
	}
	if h := v.RootHealth(); !h.EndsSoon || h.Purpose != signer.PurposePolicyBundle {
		t.Fatalf("root health: %+v", h)
	}
	now = now.Add(2 * time.Hour)
	if err := v.UpdateKeys(publish(oldRoot)); err == nil {
		t.Fatal("the old root after the overlap")
	}
	if err := v.UpdateKeys(publish(newRoot)); err != nil {
		t.Fatalf("the new root: %v", err)
	}
	// Without the chain the new root is refused.
	trust.RootChain = nil
	v2, _ := bundle.NewVerifier(trust, clock, filepath.Join(t.TempDir(), "root-chain.json"))
	if err := v2.UpdateKeys(publish(newRoot)); err == nil {
		t.Fatal("the new root without the chain")
	}
}
