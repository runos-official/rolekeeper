package roottrust_test

import (
	"errors"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer/jws"
	"github.com/runos-official/rolekeeper/signer/roottrust"
)

// Once a handover is accepted the old root signs nothing new.
// A document counts when the current root signed it, or the predecessor
// signed it before the handover and its overlap has not ended.
func TestTheOldRootSignsNothingNewAfterTheHandover(t *testing.T) {
	a, b := newRoot(t), newRoot(t)
	clk := &clock{t0}
	tr, _ := roottrust.New(a.r, clk.now)
	if _, err := tr.Verify(docAt(t, a, t0.Add(time.Hour))); err != nil {
		t.Fatalf("before any handover the pin signs at any time: %v", err)
	}
	if _, err := tr.InstallChain(chain(t, link(t, a, b, 1, t0, 30*day))); err != nil {
		t.Fatal(err)
	}
	clk.t = t0.Add(day)
	if _, err := tr.Verify(docAt(t, a, t0.Add(-time.Minute))); err != nil {
		t.Fatalf("signed by the old root before the handover, inside the overlap: %v", err)
	}
	if _, err := tr.Verify(docAt(t, a, t0.Add(time.Minute))); !errors.Is(err, roottrust.ErrRootRetired) {
		t.Fatalf("signed by the old root after the handover: %v", err)
	}
	untimed, _ := jws.Sign(a.s, "runos.keyset+jwt", []byte(`{"x":1}`))
	if _, err := tr.Verify(untimed); !errors.Is(err, roottrust.ErrRootRetired) {
		t.Fatalf("an old-root document without a signing time: %v", err)
	}
	if _, err := tr.Verify(docAt(t, b, t0.Add(-time.Hour))); err != nil {
		t.Fatalf("the current root: %v", err)
	}
	clk.t = t0.Add(30 * day)
	if _, err := tr.Verify(docAt(t, a, t0.Add(-time.Minute))); !errors.Is(err, roottrust.ErrRootExpired) {
		t.Fatalf("after the overlap: %v", err)
	}
}

// Only the direct predecessor keeps an overlap: after a -> b -> c, a's
// documents count no more, whatever a's own overlap says.
func TestOnlyThePredecessorSignsInTheOverlap(t *testing.T) {
	a, b, c := newRoot(t), newRoot(t), newRoot(t)
	clk := &clock{t0.Add(2 * time.Hour)}
	tr, _ := roottrust.New(a.r, clk.now)
	if _, err := tr.InstallChain(chain(t, link(t, a, b, 1, t0, 30*day), link(t, b, c, 2, t0.Add(time.Hour), 30*day))); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Verify(docAt(t, a, t0.Add(-time.Hour))); err == nil {
		t.Fatal("a root two handovers back still signs")
	}
	if _, err := tr.Verify(docAt(t, b, t0.Add(30*time.Minute))); err != nil {
		t.Fatalf("the predecessor before its handover: %v", err)
	}
}

// Rank orders the roots of the chain (0 is the pin); a view keeps the rank
// of the document it holds and refuses one from an earlier root. ValidUntil
// is the instant a document stops counting, and Gen moves with the chain.
func TestRankValidUntilAndGen(t *testing.T) {
	a, b, stranger := newRoot(t), newRoot(t), newRoot(t)
	clk := &clock{t0}
	tr, _ := roottrust.New(a.r, clk.now)
	g0 := tr.Gen()
	byA := doc(t, a)
	if u, err := tr.ValidUntil(byA); err != nil || !u.IsZero() {
		t.Fatalf("the pin before a handover: %v %v", u, err)
	}
	if _, err := tr.InstallChain(chain(t, link(t, a, b, 1, t0, 30*day))); err != nil {
		t.Fatal(err)
	}
	if tr.Gen() == g0 {
		t.Fatal("the generation did not move with the chain")
	}
	if r, ok := tr.Rank(byA); !ok || r != 0 {
		t.Fatalf("rank of the pin: %d %v", r, ok)
	}
	if r, ok := tr.Rank(doc(t, b)); !ok || r != 1 {
		t.Fatalf("rank of the new root: %d %v", r, ok)
	}
	if _, ok := tr.Rank(doc(t, stranger)); ok {
		t.Fatal("a stranger has a rank")
	}
	if u, err := tr.ValidUntil(byA); err != nil || !u.Equal(t0.Add(30*day-roottrust.ClockMargin)) {
		t.Fatalf("the old root's document: %v %v", u, err)
	}
	if u, err := tr.ValidUntil(doc(t, b)); err != nil || !u.IsZero() {
		t.Fatalf("the new root's document: %v %v", u, err)
	}
	if _, err := tr.ValidUntil(docAt(t, a, t0.Add(time.Minute))); !errors.Is(err, roottrust.ErrRootRetired) {
		t.Fatalf("a document the old root signed after the handover: %v", err)
	}
}
