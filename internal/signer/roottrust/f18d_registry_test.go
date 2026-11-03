package roottrust_test

import (
	"crypto"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
)

// One registry names every root-signed artifact, and one function
// per form checks it under the chain rule. The test walks the registry:
// for each artifact the old root's document from after the handover is
// refused, its document from before counts in the overlap, the new root's
// counts, and a document of another type is refused.
func TestF18dOneFunctionChecksEveryRootSignedArtifact(t *testing.T) {
	a, b := newRoot(t), newRoot(t)
	clk := &clock{t0.Add(time.Hour)}
	tr, _ := roottrust.New(a.r, clk.now)
	if _, err := tr.InstallChain(chain(t, link(t, a, b, 1, t0, 30*day))); err != nil {
		t.Fatal(err)
	}
	if len(roottrust.Artifacts) < 6 {
		t.Fatalf("the registry lists %d artifacts", len(roottrust.Artifacts))
	}
	for _, art := range roottrust.Artifacts {
		t.Run(art.Name, func(t *testing.T) {
			if art.Raw {
				msg := []byte("artifact " + art.Name)
				sign := func(r root) []byte {
					s, err := r.s.Sign(nil, msg, crypto.Hash(0))
					if err != nil {
						t.Fatal(err)
					}
					return s
				}
				if err := roottrust.VerifyRawArtifact(tr, art.Name, msg, sign(a), t0.Add(time.Minute)); !errors.Is(err, roottrust.ErrRootRetired) {
					t.Fatalf("old root after the handover: %v", err)
				}
				if err := roottrust.VerifyRawArtifact(tr, art.Name, msg, sign(a), time.Time{}); !errors.Is(err, roottrust.ErrRootRetired) {
					t.Fatalf("old root with no signing time: %v", err)
				}
				if err := roottrust.VerifyRawArtifact(tr, art.Name, msg, sign(a), t0.Add(-time.Minute)); err != nil {
					t.Fatalf("old root before the handover: %v", err)
				}
				if err := roottrust.VerifyRawArtifact(tr, art.Name, msg, sign(b), time.Time{}); err != nil {
					t.Fatalf("new root: %v", err)
				}
				return
			}
			signAt := func(r root, typ string, at time.Time) string {
				w, err := jws.Sign(r.s, typ, []byte(`{"issued_at":"`+at.UTC().Format(time.RFC3339)+`"}`))
				if err != nil {
					t.Fatal(err)
				}
				return w
			}
			if _, err := roottrust.VerifyArtifact(tr, art.Name, signAt(a, art.Typ, t0.Add(time.Minute))); !errors.Is(err, roottrust.ErrRootRetired) {
				t.Fatalf("old root after the handover: %v", err)
			}
			if _, err := roottrust.VerifyArtifact(tr, art.Name, signAt(a, art.Typ, t0.Add(-time.Minute))); err != nil {
				t.Fatalf("old root before the handover: %v", err)
			}
			if _, err := roottrust.VerifyArtifact(tr, art.Name, signAt(b, art.Typ, clk.t)); err != nil {
				t.Fatalf("new root: %v", err)
			}
			if _, err := roottrust.VerifyArtifact(tr, art.Name, signAt(b, "other+jwt", clk.t)); err == nil {
				t.Fatal("a document of another type")
			}
		})
	}
	if _, err := roottrust.VerifyArtifact(tr, "no such artifact", doc(t, b)); err == nil {
		t.Fatal("an artifact outside the registry")
	}
	if !slices.ContainsFunc(roottrust.Artifacts, func(a roottrust.Artifact) bool { return a.Name == roottrust.ArtKeySet && a.ReSign }) {
		t.Fatal("key sets are re-signed at a handover")
	}
}
