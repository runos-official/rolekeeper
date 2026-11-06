package keys_test

import (
	"errors"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
	"github.com/runos-official/rolekeeper/signer/keys"
)

// signOffline plays the offline root: it signs exactly the document in the
// request, the way the ceremony tool does.
func signOffline(t *testing.T, f *fixture, req keys.Request) string {
	t.Helper()
	return must(jws.Sign(f.root, keys.DocType, req.DocJSON))
}

// The online side never holds the root. It prepares a request, the offline
// side signs it, the online side verifies the signature and commits.
func TestOfflineRootPublishNeedsNoRootOnline(t *testing.T) {
	f := setup(t)
	p := signer.PurposeKubernetesIssuer
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	req := must(f.m.PreparePublish(f.ctx, p))
	if req.Kind != keys.RequestPublish || req.Purpose != p || len(req.DocJSON) == 0 {
		t.Fatalf("bad request: %+v", req)
	}
	signed := signOffline(t, f, req)
	if err := f.m.CommitPublish(p, signed, f.root.Public(), f.rootAlg); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(signed); err != nil {
		t.Fatalf("a verifier must accept the committed set: %v", err)
	}
	if got := f.m.Doc(p).Version; got != req.Doc.Version {
		t.Fatalf("manager is at version %d, request said %d", got, req.Doc.Version)
	}
}

func TestOfflineRootCommitRefusesWhatTheRootDidNotSign(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	must(f.m.Bootstrap(f.ctx, p, signer.AlgES256))
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgES256); err != nil {
		t.Fatal(err)
	}
	req := must(f.m.PreparePublish(f.ctx, p))

	// 1. signed by an online key, not the root
	online := must(f.m.ActiveSigner(f.ctx, p))
	forged := must(jws.Sign(online, keys.DocType, req.DocJSON))
	if err := f.m.CommitPublish(p, forged, f.root.Public(), f.rootAlg); err == nil {
		t.Fatal("a set signed by an online key must be refused")
	}
	// 2. the root signed a different document than the one prepared
	other := req.Doc
	other.Version += 5
	otherJSON := mustJSON(other)
	swapped := must(jws.Sign(f.root, keys.DocType, otherJSON))
	if err := f.m.CommitPublish(p, swapped, f.root.Public(), f.rootAlg); !errors.Is(err, keys.ErrRequestMismatch) {
		t.Fatalf("a different document must be refused as a mismatch, got %v", err)
	}
	// 3. nothing was committed by the failures
	if f.m.Doc(p).Version != req.Doc.Version-1 {
		t.Fatalf("a refused commit changed the manager to version %d", f.m.Doc(p).Version)
	}
	// 4. the right signature still works, once
	good := signOffline(t, f, req)
	if err := f.m.CommitPublish(p, good, f.root.Public(), f.rootAlg); err != nil {
		t.Fatal(err)
	}
	if err := f.m.CommitPublish(p, good, f.root.Public(), f.rootAlg); !errors.Is(err, keys.ErrNoRequest) {
		t.Fatalf("a request commits once, got %v", err)
	}
}

func TestOfflineRootCommitRefusesAStaleRequest(t *testing.T) {
	f := setup(t)
	p := signer.PurposeVPNLease
	must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	stale := must(f.m.PreparePublish(f.ctx, p))
	staleSigned := signOffline(t, f, stale)
	// The state moves on before the stale signature comes back.
	f.clk.advance(time.Minute)
	if _, err := f.m.Publish(f.ctx, p, f.root); err != nil {
		t.Fatal(err)
	}
	if err := f.m.CommitPublish(p, staleSigned, f.root.Public(), f.rootAlg); err == nil {
		t.Fatal("a signature for an old request must be refused")
	}
}

func TestOfflineRootCompromiseResetWithoutRootOnline(t *testing.T) {
	f := setup(t)
	p := signer.PurposeKubernetesIssuer
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	bad := pinned.Active().Kid
	req := must(f.m.PrepareCompromise(f.ctx, p, bad))
	if req.Kind != keys.RequestCompromise || req.Kid != bad || req.Doc.Epoch != pinned.Epoch+1 || req.Doc.Version != 1 {
		t.Fatalf("bad compromise request: %+v", req)
	}
	signed := signOffline(t, f, req)
	if err := f.m.CommitCompromise(p, signed, f.root.Public(), f.rootAlg); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(signed); err != nil {
		t.Fatalf("verifier must accept the root-signed reset: %v", err)
	}
	if _, _, err := v.Lookup(bad); err == nil {
		t.Fatal("the compromised key must be gone from the verifier")
	}
	if f.m.Doc(p).Find(bad) != nil {
		t.Fatal("the compromised key must be gone from the manager")
	}
	// The compromised key is disabled in custody.
	if _, err := f.b.Sign(f.ctx, signer.SignRequest{KeyID: bad, Purpose: p, Digest: make([]byte, 64), Hash: 0}); !errors.Is(err, signer.ErrKeyDisabled) {
		t.Fatalf("compromised key must be disabled in custody, got %v", err)
	}
}

func mustJSON(v any) []byte { return must(jsonMarshal(v)) }
