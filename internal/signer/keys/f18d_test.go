package keys_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
)

// signDoc signs the manager's current set of p with by, moved up by bump
// versions and dated at.
func signDoc(t *testing.T, f *fixture, p signer.Purpose, by *signer.Signer, bump uint64, at time.Time) string {
	t.Helper()
	d := f.m.Doc(p)
	d.Version += bump
	d.IssuedAt = at
	return must(jws.Sign(by, keys.DocType, must(json.Marshal(d))))
}

// A running view re-checks the root of the set it holds at each
// use. When the old root's overlap ends it stops verifying at once, without
// a restart, and the error names the runbook step.
func TestF18dARunningViewStopsAtTheOverlapEnd(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	nr := newRootSigner(t, f)
	before := f.clk.now().Add(-time.Minute)
	held := signDoc(t, f, p, f.root, 1, before)
	tr := must(roottrust.Load(roottrust.Config{OneShot: true, Pin: rootRec(f.root), Chain: handoverChain(t, f.root, nr, f.clk.now(), time.Hour), Now: f.clk.now}))
	v := must(keys.NewViewRoots(p, tr, pinned, filepath.Join(t.TempDir(), "v")))
	if err := v.Update(held); err != nil {
		t.Fatalf("the old root's set from before the handover: %v", err)
	}
	kid := pinned.Active().Kid
	if _, _, err := v.Lookup(kid); err != nil {
		t.Fatalf("inside the overlap: %v", err)
	}
	f.clk.advance(time.Hour)
	if _, _, err := v.Lookup(kid); !errors.Is(err, roottrust.ErrRootExpired) {
		t.Fatalf("a running view after the overlap: %v", err)
	}
	// The new root's set brings it back.
	if err := v.Update(signDoc(t, f, p, nr, 2, f.clk.now())); err != nil {
		t.Fatalf("the new root's set: %v", err)
	}
	if _, _, err := v.Lookup(kid); err != nil {
		t.Fatalf("after the new root's set: %v", err)
	}
}

// The old root signs nothing new after the handover, and a view
// never goes back to an earlier root than the one that signed its set,
// whatever version or date the earlier root writes.
func TestF18dTheOldRootCannotOutrankTheNewRoot(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	nr := newRootSigner(t, f)
	handover := f.clk.now()
	tr := must(roottrust.Load(roottrust.Config{OneShot: true, Pin: rootRec(f.root), Chain: handoverChain(t, f.root, nr, handover, 30*24*time.Hour), Now: f.clk.now}))
	state := filepath.Join(t.TempDir(), "v")
	v := must(keys.NewViewRoots(p, tr, pinned, state))
	f.clk.advance(time.Hour)
	if err := v.Update(signDoc(t, f, p, f.root, 1, f.clk.now())); !errors.Is(err, roottrust.ErrRootRetired) {
		t.Fatalf("an old-root set dated after the handover: %v", err)
	}
	if err := v.Update(signDoc(t, f, p, nr, 1, f.clk.now())); err != nil {
		t.Fatalf("the new root: %v", err)
	}
	stolen := signDoc(t, f, p, f.root, 1000, handover.Add(-time.Minute))
	if err := v.Update(stolen); !errors.Is(err, keys.ErrRootRank) {
		t.Fatalf("a back-dated old-root set over the new root's: %v", err)
	}
	again := must(keys.NewViewRoots(p, tr, pinned, state))
	if err := again.Update(stolen); !errors.Is(err, keys.ErrRootRank) {
		t.Fatalf("after a restart: %v", err)
	}
	// The identity service's install keeps the same order.
	req := must(f.m.PreparePublish(f.ctx, p))
	if err := f.m.CommitPublishRoots(p, must(jws.Sign(nr, keys.DocType, req.DocJSON)), tr); err != nil {
		t.Fatal(err)
	}
	req = must(f.m.PreparePublish(f.ctx, p))
	var d keys.Doc
	_ = json.Unmarshal(req.DocJSON, &d)
	if err := f.m.CommitPublishRoots(p, must(jws.Sign(f.root, keys.DocType, req.DocJSON)), tr); !errors.Is(err, roottrust.ErrRootRetired) {
		t.Fatalf("the install of an old-root set after the new root's: %v", err)
	}
}
