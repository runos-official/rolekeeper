package roottrust_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer/roottrust"
)

// cutoff makes an overlap cutoff signed by by (the current root, or not).
func cutoff(t *testing.T, by, cur, retire root, seq uint64, issued, until time.Time) []byte {
	t.Helper()
	c, err := roottrust.NewCutoff(cur.r, retire.r, seq, issued, until)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := c.Payload()
	sig, err := roottrust.SignCutoff(by.s, p)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(roottrust.Bundle{Statement: p, New: sig})
	return out
}

// The new root alone can end the old root's overlap
// early, when the old root may be compromised. The cutoff is a link of the
// chain (sequence numbered), only shortens, and every verifier honours it
// at its next use.
func TestTheNewRootEndsTheOverlapEarly(t *testing.T) {
	a, b, c := newRoot(t), newRoot(t), newRoot(t)
	clk := &clock{t0.Add(time.Hour)}
	tr, _ := roottrust.New(a.r, clk.now)
	ab := link(t, a, b, 1, t0, 30*day)
	if _, err := tr.InstallChain(chain(t, ab)); err != nil {
		t.Fatal(err)
	}
	byA := doc(t, a)
	if _, err := tr.Verify(byA); err != nil {
		t.Fatalf("inside the overlap: %v", err)
	}
	g := tr.Gen()
	end := t0.Add(2 * time.Hour)
	cut := cutoff(t, b, b, a, 2, t0.Add(time.Hour), end)
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"signed by the old root":         {cutoff(t, a, b, a, 2, t0.Add(time.Hour), end), roottrust.ErrBadHandover},
		"signed by a stranger":           {cutoff(t, c, b, a, 2, t0.Add(time.Hour), end), roottrust.ErrBadHandover},
		"an extension":                   {cutoff(t, b, b, a, 2, t0.Add(time.Hour), t0.Add(31*day)), roottrust.ErrBadStatement},
		"a skipped sequence":             {cutoff(t, b, b, a, 3, t0.Add(time.Hour), end), roottrust.ErrMissingLink},
		"a root that is not the current": {cutoff(t, a, a, b, 2, t0.Add(time.Hour), end), roottrust.ErrNotCurrent},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tr2, _ := roottrust.New(a.r, clk.now)
			_, _ = tr2.InstallChain(chain(t, ab))
			if _, err := tr2.InstallChain(chain(t, ab, tc.in)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := tr.InstallChain(chain(t, ab, cut)); err != nil {
		t.Fatalf("the cutoff: %v", err)
	}
	if tr.Gen() == g || tr.Seq() != 2 || tr.Current().KeyID != b.r.KeyID {
		t.Fatalf("after the cutoff: gen %d seq %d current %s", tr.Gen(), tr.Seq(), tr.Current().KeyID)
	}
	if _, err := tr.Verify(byA); err != nil {
		t.Fatalf("before the new end: %v", err)
	}
	clk.t = end.Add(-roottrust.ClockMargin)
	if _, err := tr.Verify(byA); !errors.Is(err, roottrust.ErrRootExpired) {
		t.Fatalf("at the new end (less the clock margin): %v", err)
	}
	// A second cutoff may shorten again, never lengthen; the chain carries
	// it and the next handover follows it.
	if _, err := tr.Apply(cutoff(t, b, b, a, 3, t0.Add(time.Hour), end.Add(time.Minute))); !errors.Is(err, roottrust.ErrBadStatement) {
		t.Fatalf("a later end: %v", err)
	}
	if _, err := tr.Apply(link(t, b, c, 3, t0.Add(2*time.Hour), day)); err != nil {
		t.Fatalf("a handover after the cutoff: %v", err)
	}
	out, _ := tr.ChainJSON()
	fresh, _ := roottrust.New(a.r, clk.now)
	if _, err := fresh.InstallChain(out); err != nil || fresh.Seq() != 3 || fresh.Current().KeyID != c.r.KeyID {
		t.Fatalf("the chain with the cutoff round-trips: %v", err)
	}
	links, err := roottrust.DecodeChain(out)
	if err != nil || len(links) != 3 || links[1].Kind != roottrust.KindCutoff {
		t.Fatalf("decode: %v %+v", err, links)
	}
	if cur, ok := roottrust.CurrentRoot(links); !ok || cur.KeyID != c.r.KeyID {
		t.Fatalf("current root of the chain: %+v", cur)
	}
}

// Verifiers' clocks differ, so the old root's overlap ends
// ClockMargin early on every verifier.
func TestTheOverlapEndsAClockMarginEarly(t *testing.T) {
	a, b := newRoot(t), newRoot(t)
	clk := &clock{t0}
	tr, _ := roottrust.New(a.r, clk.now)
	if _, err := tr.InstallChain(chain(t, link(t, a, b, 1, t0, day))); err != nil {
		t.Fatal(err)
	}
	clk.t = t0.Add(day - roottrust.ClockMargin - time.Second)
	if _, err := tr.Verify(doc(t, a)); err != nil {
		t.Fatalf("before the margin: %v", err)
	}
	clk.t = t0.Add(day - roottrust.ClockMargin)
	if _, err := tr.Verify(doc(t, a)); !errors.Is(err, roottrust.ErrRootExpired) {
		t.Fatalf("inside the margin: %v", err)
	}
	if u, _ := tr.ValidUntil(doc(t, b)); !u.IsZero() {
		t.Fatal("the current root has an end")
	}
	if tr.CurrentRank() != 1 {
		t.Fatalf("current rank %d", tr.CurrentRank())
	}
}

// A verifier that forgets its chain takes an older one after a
// restart, so Load needs a state path unless the caller says it is a
// one-shot check.
func TestLoadNeedsAStatePath(t *testing.T) {
	a := newRoot(t)
	if _, err := roottrust.Load(roottrust.Config{Pin: a.r}); !errors.Is(err, roottrust.ErrState) {
		t.Fatalf("no state path: %v", err)
	}
	if _, err := roottrust.Load(roottrust.Config{Pin: a.r, OneShot: true}); err != nil {
		t.Fatalf("a one-shot check: %v", err)
	}
}
