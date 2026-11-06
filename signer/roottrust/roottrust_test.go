package roottrust_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
	"github.com/runos-official/rolekeeper/signer/roottrust"
)

var t0 = time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type root struct {
	s *signer.Signer
	r roottrust.Root
}

func newRoot(t *testing.T) root {
	t.Helper()
	b := signer.NewOfflineRootBackend()
	k, err := b.CreateKey(context.Background(), signer.PurposeKeySetRoot, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signer.New(context.Background(), b, k.ID, signer.PurposeKeySetRoot)
	if err != nil {
		t.Fatal(err)
	}
	return root{s: s, r: roottrust.Root{KeyID: k.ID, Alg: signer.AlgEdDSA, PublicDER: k.PublicDER}}
}

// doc signs a stand-in key-set document with a root.
// doc signs a stand-in document issued an hour before t0 (before any
// handover in these tests).
func doc(t *testing.T, r root) string {
	t.Helper()
	return docAt(t, r, t0.Add(-time.Hour))
}

// docAt signs a stand-in document with its signing time.
func docAt(t *testing.T, r root, at time.Time) string {
	t.Helper()
	w, err := jws.Sign(r.s, "runos.keyset+jwt", []byte(`{"x":1,"issued_at":"`+at.UTC().Format(time.RFC3339Nano)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestTrustAcceptsBothRootsInTheOverlapAndOnlyTheNewOneAfter(t *testing.T) {
	a, b := newRoot(t), newRoot(t)
	clk := &clock{t0}
	tr, err := roottrust.New(a.r, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Verify(doc(t, b)); err == nil {
		t.Fatal("before a handover only the pinned root signs")
	}
	if _, err := tr.Apply(link(t, a, b, 1, t0, 30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(tr.Accepted()) != 2 || tr.Current().KeyID != b.r.KeyID {
		t.Fatalf("accepted: %v", tr.Accepted())
	}
	for _, r := range []root{a, b} {
		if _, err := tr.Verify(doc(t, r)); err != nil {
			t.Fatalf("inside the overlap: %v", err)
		}
	}
	clk.t = t0.Add(30*24*time.Hour - roottrust.ClockMargin - time.Second)
	if _, err := tr.Verify(doc(t, a)); err != nil {
		t.Fatalf("the last second of the overlap (less the clock margin): %v", err)
	}
	clk.t = t0.Add(30 * 24 * time.Hour)
	_, err = tr.Verify(doc(t, a))
	if !errors.Is(err, roottrust.ErrRootExpired) || !errors.Is(err, jws.ErrBadSignature) {
		t.Fatalf("after the overlap the old root is refused: %v", err)
	}
	if _, err := tr.Verify(doc(t, b)); err != nil {
		t.Fatalf("the new root keeps signing: %v", err)
	}
	if len(tr.Accepted()) != 1 {
		t.Fatalf("accepted: %v", tr.Accepted())
	}
}

func TestApplyRefusesHandoversThatAreNotWhatTheyClaim(t *testing.T) {
	a, b, c, stranger := newRoot(t), newRoot(t), newRoot(t), newRoot(t)
	good := link(t, a, b, 1, t0, 24*time.Hour)

	mod := func(f func(*roottrust.Bundle)) []byte {
		var bd roottrust.Bundle
		if err := json.Unmarshal(good, &bd); err != nil {
			t.Fatal(err)
		}
		f(&bd)
		out, _ := json.Marshal(bd)
		return out
	}
	st, _ := roottrust.NewStatement(a.r, b.r, 1, t0, 24*time.Hour)
	payload, _ := st.Payload()
	strangerSig, _ := roottrust.SignSide(stranger.s, payload)

	cases := map[string]struct {
		in   []byte
		want error
	}{
		"no signature of the new root":     {mod(func(b *roottrust.Bundle) { b.New = "" }), roottrust.ErrBadHandover},
		"no signature of the old root":     {mod(func(b *roottrust.Bundle) { b.Old = "" }), roottrust.ErrBadHandover},
		"new root signature by a stranger": {mod(func(b *roottrust.Bundle) { b.New = strangerSig }), roottrust.ErrBadHandover},
		"old root signature by a stranger": {mod(func(b *roottrust.Bundle) { b.Old = strangerSig }), roottrust.ErrBadHandover},
		"signatures swapped":               {mod(func(b *roottrust.Bundle) { b.Old, b.New = b.New, b.Old }), roottrust.ErrBadHandover},
		"statement changed after signing": {mod(func(bd *roottrust.Bundle) {
			s2, _ := roottrust.NewStatement(a.r, c.r, 1, t0, 24*time.Hour)
			bd.Statement, _ = s2.Payload()
		}), roottrust.ErrBadHandover},
		"a handover not from the pinned root": {link(t, stranger, c, 1, t0, time.Hour), roottrust.ErrNotCurrent},
		"overlap too long":                    {nil, roottrust.ErrBadStatement},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tr, _ := roottrust.New(a.r, func() time.Time { return t0 })
			if name == "overlap too long" {
				if _, err := roottrust.NewStatement(a.r, b.r, 1, t0, roottrust.MaxOverlap+time.Hour); !errors.Is(err, tc.want) {
					t.Fatalf("got %v", err)
				}
				return
			}
			if _, err := tr.Apply(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if len(tr.Accepted()) != 1 || tr.Current().KeyID != a.r.KeyID {
				t.Fatal("a refused handover must change nothing")
			}
		})
	}
	// A statement to the same key, or without an overlap, cannot be made.
	if _, err := roottrust.NewStatement(a.r, a.r, 1, t0, time.Hour); !errors.Is(err, roottrust.ErrBadStatement) {
		t.Fatalf("same key: %v", err)
	}
	if _, err := roottrust.NewStatement(a.r, b.r, 1, t0, 0); !errors.Is(err, roottrust.ErrBadStatement) {
		t.Fatalf("no overlap: %v", err)
	}
}

func TestAForkFromTheRetiredRootIsRefused(t *testing.T) {
	a, b, c := newRoot(t), newRoot(t), newRoot(t)
	tr, _ := roottrust.New(a.r, func() time.Time { return t0 })
	if _, err := tr.Apply(link(t, a, b, 1, t0, 24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// The same handover again changes nothing.
	if _, err := tr.Apply(link(t, a, b, 1, t0, 24*time.Hour)); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	// While the old root is still valid, a second handover from it to another
	// key is refused: only the newest root hands over, and handover 1 is
	// already another one (a fork).
	if _, err := tr.Apply(link(t, a, c, 1, t0, 24*time.Hour)); !errors.Is(err, roottrust.ErrFork) {
		t.Fatalf("fork: %v", err)
	}
	// A chain a -> b -> c works.
	if _, err := tr.Apply(link(t, b, c, 2, t0, 24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if tr.Current().KeyID != c.r.KeyID {
		t.Fatal("current root")
	}
}

func TestStateSurvivesARestartAndFailsClosedWhenChanged(t *testing.T) {
	a, b, other := newRoot(t), newRoot(t), newRoot(t)
	clk := &clock{t0}
	path := filepath.Join(t.TempDir(), "roots.json")
	tr, err := roottrust.Open(a.r, path, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Apply(link(t, a, b, 1, t0, 24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	clk.t = t0.Add(48 * time.Hour)
	again, err := roottrust.Open(a.r, path, clk.now)
	if err != nil {
		t.Fatalf("restart after the overlap: %v", err)
	}
	if _, err := again.Verify(doc(t, a)); !errors.Is(err, roottrust.ErrRootExpired) {
		t.Fatalf("a restart must not bring the old root back: %v", err)
	}
	if _, err := again.Verify(doc(t, b)); err != nil {
		t.Fatal(err)
	}
	if _, err := roottrust.Open(other.r, path, clk.now); !errors.Is(err, roottrust.ErrState) {
		t.Fatalf("another pin: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := roottrust.Open(a.r, path, clk.now); !errors.Is(err, roottrust.ErrState) {
		t.Fatalf("damaged state: %v", err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestDecodeRefusesUnknownFieldsAndForeignEncodings(t *testing.T) {
	a, b := newRoot(t), newRoot(t)
	st, _ := roottrust.NewStatement(a.r, b.r, 1, t0, time.Hour)
	p, _ := st.Payload()
	extra := append(p[:len(p)-1:len(p)-1], []byte(`,"also":1}`)...)
	in, _ := json.Marshal(roottrust.Bundle{Statement: extra})
	if _, _, err := roottrust.Decode(in); !errors.Is(err, roottrust.ErrBadStatement) {
		t.Fatalf("unknown field: %v", err)
	}
	spaced := append([]byte(" "), p...)
	in, _ = json.Marshal(roottrust.Bundle{Statement: spaced})
	if _, _, err := roottrust.Decode(in); !errors.Is(err, roottrust.ErrBadStatement) {
		t.Fatalf("other encoding: %v", err)
	}
}
