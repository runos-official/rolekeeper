package bundle_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/revlog"
	"github.com/runos-official/rolekeeper/signer/roottrust"
	"github.com/runos-official/rolekeeper/signer/token"
)

// A running applier stops verifying bundles at the instant the old
// root's overlap ends, and takes nothing the old root signs after the
// handover.
func TestARunningApplierStopsAtTheOverlapEnd(t *testing.T) {
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
	doc, _ := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	oldSet, _ := km.Publish(ctx, signer.PurposePolicyBundle, oldRoot)
	now = now.Add(time.Minute)
	link, _ := roottrust.HandoverBundle(oldRoot, newRoot, 1, now, time.Hour)
	ch, _ := roottrust.EncodeChain([][]byte{link})
	v, err := bundle.NewVerifier(bundle.Trust{Issuer: issuerName, Cluster: "cl-1", RootPublicDER: oldRoot.Info().PublicDER, RootAlg: signer.AlgEdDSA,
		BundleKeys: doc, RootChain: ch}, clock, filepath.Join(t.TempDir(), "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateKeys(oldSet); err != nil {
		t.Fatalf("the old root's set from before the handover: %v", err)
	}
	r := &rig{issuer: &token.Issuer{Keys: km, Name: issuerName, Now: clock}}
	seal := func() []byte { r.now = now; return r.seal(t, body(uint64(now.Unix()))) }
	if _, err := v.Verify(seal()); err != nil {
		t.Fatalf("a bundle inside the overlap: %v", err)
	}
	late, _ := km.Publish(ctx, signer.PurposePolicyBundle, oldRoot)
	if err := v.UpdateKeys(late); err == nil {
		t.Fatal("the applier took a set the old root signed after the handover")
	}
	now = now.Add(time.Hour)
	if _, err := v.Verify(seal()); err == nil {
		t.Fatal("a running applier took a bundle after the old root's overlap ended")
	}
	fresh, _ := km.Publish(ctx, signer.PurposePolicyBundle, newRoot)
	if err := v.UpdateKeys(fresh); err != nil {
		t.Fatalf("the new root's set: %v", err)
	}
	if _, err := v.Verify(seal()); err != nil {
		t.Fatalf("a bundle under the new root's set: %v", err)
	}
}

// The applier keeps the highest root chain beside its state, so a
// restart with an older trust file keeps the chain; it has no memory-only
// verifier.
func TestTheApplierKeepsItsRootChainAcrossARestart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	root := func() *signer.Signer {
		off := signer.NewOfflineRootBackend()
		k, _ := off.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
		s, _ := signer.New(ctx, off, k.ID, signer.PurposeKeySetRoot)
		return s
	}
	oldRoot, newRoot := root(), root()
	log, _ := revlog.Open(filepath.Join(t.TempDir(), "rev.log"))
	t.Cleanup(func() { log.Close() })
	km := keys.NewManager(signer.NewSoftBackend(), log, clock)
	doc, _ := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	link, _ := roottrust.HandoverBundle(oldRoot, newRoot, 1, now, time.Hour)
	ch, _ := roottrust.EncodeChain([][]byte{link})
	trust := bundle.Trust{Issuer: issuerName, Cluster: "cl-1", RootPublicDER: oldRoot.Info().PublicDER, RootAlg: signer.AlgEdDSA, BundleKeys: doc, RootChain: ch}
	if _, err := bundle.NewVerifier(trust, clock, ""); err == nil {
		t.Fatal("an applier verifier with no state path")
	}
	state := filepath.Join(t.TempDir(), "root-chain.json")
	if _, err := bundle.NewVerifier(trust, clock, state); err != nil {
		t.Fatal(err)
	}
	older := trust
	older.RootChain = nil
	v, err := bundle.NewVerifier(older, clock, state)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	fresh, _ := km.Publish(ctx, signer.PurposePolicyBundle, newRoot)
	if err := v.UpdateKeys(fresh); err != nil {
		t.Fatalf("after a restart with an older trust file the new root counts: %v", err)
	}
}

// The applier keeps its policy-bundle key set beside its
// state, so the precedence high-water (the root that signed the set it
// holds) survives a restart: an old-root set is refused after one.
func TestTheApplierKeepsItsKeySetAndRootOrderAcrossARestart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	root := func() *signer.Signer {
		off := signer.NewOfflineRootBackend()
		k, _ := off.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
		s, _ := signer.New(ctx, off, k.ID, signer.PurposeKeySetRoot)
		return s
	}
	oldRoot, newRoot := root(), root()
	log, _ := revlog.Open(filepath.Join(t.TempDir(), "rev.log"))
	t.Cleanup(func() { log.Close() })
	km := keys.NewManager(signer.NewSoftBackend(), log, clock)
	doc, _ := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	oldSet, _ := km.Publish(ctx, signer.PurposePolicyBundle, oldRoot) // before the handover
	now = now.Add(time.Minute)
	link, _ := roottrust.HandoverBundle(oldRoot, newRoot, 1, now, 30*24*time.Hour)
	ch, _ := roottrust.EncodeChain([][]byte{link})
	trust := bundle.Trust{Issuer: issuerName, Cluster: "cl-1", RootPublicDER: oldRoot.Info().PublicDER, RootAlg: signer.AlgEdDSA, BundleKeys: doc, RootChain: ch}
	state := filepath.Join(t.TempDir(), "root-chain.json")
	v, err := bundle.NewVerifier(trust, clock, state)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	newSet, _ := km.Publish(ctx, signer.PurposePolicyBundle, newRoot)
	if err := v.UpdateKeys(newSet); err != nil {
		t.Fatal(err)
	}
	again, err := bundle.NewVerifier(trust, clock, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.UpdateKeys(oldSet); !errors.Is(err, roottrust.ErrRootRank) {
		t.Fatalf("after a restart, the old root's set over the new root's: %v", err)
	}
}
