package keys_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/roottrust"
)

func rootRec(s *signer.Signer) roottrust.Root {
	return roottrust.Root{KeyID: s.KeyID(), Alg: signer.AlgEdDSA, PublicDER: s.Info().PublicDER}
}

func newRootSigner(t *testing.T, f *fixture) *signer.Signer {
	t.Helper()
	off := signer.NewOfflineRootBackend()
	k := must(off.CreateKey(f.ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA))
	return must(signer.New(f.ctx, off, k.ID, signer.PurposeKeySetRoot))
}

func handoverChain(t *testing.T, from, to *signer.Signer, issued time.Time, overlap time.Duration) []byte {
	t.Helper()
	st := must(roottrust.NewStatement(rootRec(from), rootRec(to), 1, issued, overlap))
	payload := must(st.Payload())
	b := must(json.Marshal(roottrust.Bundle{Statement: payload, Old: must(roottrust.SignSide(from, payload)), New: must(roottrust.SignSide(to, payload))}))
	return must(roottrust.EncodeChain([][]byte{b}))
}

// A key set signed by the old root is accepted before and during the
// overlap and refused after it; one signed by the new root is accepted once
// the chain is installed. The same holds for the identity service's install
// (CommitPublishRoots) and for every verifier (a view over the chain).
func TestKeySetsFollowTheRootChain(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	nr := newRootSigner(t, f)
	pin := rootRec(f.root)
	overlap := 24 * time.Hour
	ch := handoverChain(t, f.root, nr, f.clk.now().Add(time.Minute), overlap)

	// Before the chain: only the pinned root.
	before := must(roottrust.Load(roottrust.Config{OneShot: true, Pin: pin, Now: f.clk.now}))
	req := must(f.m.PreparePublish(f.ctx, p))
	if err := f.m.CommitPublishRoots(p, must(jws.Sign(nr, keys.DocType, req.DocJSON)), before); err == nil {
		t.Fatal("the new root signed a set before the chain was installed")
	}
	if err := f.m.CommitPublishRoots(p, must(jws.Sign(f.root, keys.DocType, req.DocJSON)), before); err != nil {
		t.Fatalf("the pinned root before the chain: %v", err)
	}
	vb := must(keys.NewViewRoots(p, before, pinned, filepath.Join(t.TempDir(), "before")))
	if err := vb.Update(f.m.LastSigned(p)); err != nil {
		t.Fatalf("a view before the chain: %v", err)
	}

	// The chain is installed. Inside the overlap the set the old root signed
	// before the handover still counts; a new one it signs is refused
	// (only the new root signs new documents).
	tr := must(roottrust.Load(roottrust.Config{OneShot: true, Pin: pin, Chain: ch, Now: f.clk.now}))
	state := filepath.Join(t.TempDir(), "view")
	v := must(keys.NewViewRoots(p, tr, pinned, state))
	if err := v.Update(f.m.LastSigned(p)); err != nil {
		t.Fatalf("a view inside the overlap: %v", err)
	}
	f.clk.advance(2 * time.Minute)
	req = must(f.m.PreparePublish(f.ctx, p))
	inside := must(jws.Sign(f.root, keys.DocType, req.DocJSON))
	if err := f.m.CommitPublishRoots(p, inside, tr); !errors.Is(err, roottrust.ErrRootRetired) {
		t.Fatalf("the old root signing after the handover: %v", err)
	}
	if err := v.Update(inside); !errors.Is(err, roottrust.ErrRootRetired) {
		t.Fatalf("a view took a set the old root signed after the handover: %v", err)
	}

	// After the overlap the old root is refused, at the install and in the
	// view; the new root is accepted at both.
	f.clk.advance(overlap)
	req = must(f.m.PreparePublish(f.ctx, p))
	late := must(jws.Sign(f.root, keys.DocType, req.DocJSON))
	if err := f.m.CommitPublishRoots(p, late, tr); err == nil {
		t.Fatalf("the old root after the overlap: %v", err)
	}
	signedNew := must(jws.Sign(nr, keys.DocType, req.DocJSON))
	if err := f.m.CommitPublishRoots(p, signedNew, tr); err != nil {
		t.Fatalf("the new root after the overlap: %v", err)
	}
	if err := v.Update(late); err == nil {
		t.Fatalf("a view took the old root after the overlap: %v", err)
	}

	// A restart after the overlap with a stored set that only
	// the old root signed fails closed, and the error names the runbook
	// step (the new root re-signs every set before the overlap ends).
	_, err := keys.NewViewRoots(p, tr, pinned, state)
	if !errors.Is(err, roottrust.ErrRootExpired) || !strings.Contains(err.Error(), roottrust.RunbookStep) {
		t.Fatalf("restart with stored state from the retired root: %v", err)
	}
	// Re-signed by the new root in time, the stored set loads.
	fresh := filepath.Join(t.TempDir(), "fresh")
	v2 := must(keys.NewViewRoots(p, tr, pinned, fresh))
	if err := v2.Update(signedNew); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.NewViewRoots(p, tr, pinned, fresh); err != nil {
		t.Fatalf("restart with a set the new root signed: %v", err)
	}

	// A compromise reset follows the same rules.
	bad := f.m.Doc(p).Active().Kid
	creq := must(f.m.PrepareCompromise(f.ctx, p, bad))
	if err := f.m.CommitCompromiseRoots(p, must(jws.Sign(f.root, keys.DocType, creq.DocJSON)), tr); err == nil {
		t.Fatalf("a reset by the old root after the overlap: %v", err)
	}
	creq = must(f.m.PrepareCompromise(f.ctx, p, bad))
	if err := f.m.CommitCompromiseRoots(p, must(jws.Sign(nr, keys.DocType, creq.DocJSON)), tr); err != nil {
		t.Fatalf("a reset by the new root: %v", err)
	}
}

// The pinned-key entry points (NewView, CommitPublish) are the same code
// as the chain ones with a one-root trust.
func TestThePinnedKeyPathIsTheOneRootChain(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	nr := newRootSigner(t, f)
	req := must(f.m.PreparePublish(f.ctx, p))
	if err := f.m.CommitPublish(p, must(jws.Sign(nr, keys.DocType, req.DocJSON)), f.root.Public(), f.rootAlg); err == nil {
		t.Fatal("another root signed")
	}
	signed := must(jws.Sign(f.root, keys.DocType, req.DocJSON))
	if err := f.m.CommitPublish(p, signed, f.root.Public(), f.rootAlg); err != nil {
		t.Fatal(err)
	}
	v := must(keys.NewViewWithState(p, f.root.Public(), f.rootAlg, pinned, filepath.Join(t.TempDir(), "s")))
	if err := v.Update(signed); err != nil {
		t.Fatal(err)
	}
}

// A view reports, and logs once, when the set it holds is signed only by a
// root whose overlap ends within seven days (roottrust.OverlapWarning).
func TestViewRootHealthWarnsBeforeTheOverlapEnds(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	nr := newRootSigner(t, f)
	oldSet := must(f.m.Publish(f.ctx, p, f.root)) // signed before the handover
	f.clk.advance(time.Minute)
	tr := must(roottrust.Load(roottrust.Config{OneShot: true, Pin: rootRec(f.root), Chain: handoverChain(t, f.root, nr, f.clk.now(), 30*24*time.Hour), Now: f.clk.now}))
	v := must(keys.NewViewRoots(p, tr, pinned, filepath.Join(t.TempDir(), "v")))
	if h := v.RootHealth(); h.EndsSoon || h.Root != "" {
		t.Fatalf("the unsigned install pin: %+v", h)
	}
	if err := v.Update(oldSet); err != nil {
		t.Fatal(err)
	}
	if h := v.RootHealth(); h.EndsSoon || h.OverlapUntil.IsZero() || h.Purpose != p {
		t.Fatalf("a month before the end: %+v", h)
	}
	f.clk.advance(23*24*time.Hour + time.Second)
	h := v.RootHealth()
	if !h.EndsSoon || h.Root != rootRec(f.root).Fingerprint() {
		t.Fatalf("a week before the end: %+v", h)
	}
	v.RootHealth()
	if n := strings.Count(buf.String(), "must re-sign"); n != 1 || !strings.Contains(buf.String(), roottrust.RunbookStep) {
		t.Fatalf("want one log line naming the runbook, got %d:\n%s", n, buf.String())
	}
	if err := v.Update(must(f.m.Publish(f.ctx, p, nr))); err != nil {
		t.Fatal(err)
	}
	if h := v.RootHealth(); h.EndsSoon || !h.OverlapUntil.IsZero() {
		t.Fatalf("after the new root re-signed: %+v", h)
	}
}
