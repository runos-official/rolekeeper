package roottrust_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer/roottrust"
)

const day = 24 * time.Hour

// link makes a complete handover bundle with a sequence number.
func link(t *testing.T, a, b root, seq uint64, issued time.Time, overlap time.Duration) []byte {
	t.Helper()
	st, err := roottrust.NewStatement(a.r, b.r, seq, issued, overlap)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := st.Payload()
	old, err := roottrust.SignSide(a.s, payload)
	if err != nil {
		t.Fatal(err)
	}
	nw, err := roottrust.SignSide(b.s, payload)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(roottrust.Bundle{Statement: payload, Old: old, New: nw})
	return out
}

func chain(t *testing.T, links ...[]byte) []byte {
	t.Helper()
	b, err := roottrust.EncodeChain(links)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The chain a -> b -> c, walked from the pinned a: each old root signs
// until its overlap ends, the newest root always.
func TestChainWalksFromThePinnedRootAndEachOverlapEnds(t *testing.T) {
	a, b, c := newRoot(t), newRoot(t), newRoot(t)
	clk := &clock{t0}
	tr, err := roottrust.New(a.r, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	ch := chain(t, link(t, a, b, 1, t0, 10*day), link(t, b, c, 2, t0.Add(time.Hour), 20*day))
	added, err := tr.InstallChain(ch)
	if err != nil || added != 2 {
		t.Fatalf("install: %d %v", added, err)
	}
	if tr.Seq() != 2 || tr.Current().KeyID != c.r.KeyID {
		t.Fatalf("head %d %s", tr.Seq(), tr.Current().KeyID)
	}
	// Only the predecessor keeps an overlap; a is two handovers back.
	for _, r := range []root{b, c} {
		if _, err := tr.Verify(doc(t, r)); err != nil {
			t.Fatalf("inside the overlap: %v", err)
		}
	}
	if _, err := tr.Verify(doc(t, a)); !errors.Is(err, roottrust.ErrRootExpired) {
		t.Fatalf("a two handovers back: %v", err)
	}
	clk.t = t0.Add(10 * day)
	if _, err := tr.Verify(doc(t, b)); err != nil {
		t.Fatalf("b inside its overlap: %v", err)
	}
	clk.t = t0.Add(time.Hour + 20*day)
	if _, err := tr.Verify(doc(t, b)); !errors.Is(err, roottrust.ErrRootExpired) {
		t.Fatalf("b after its overlap: %v", err)
	}
	if _, err := tr.Verify(doc(t, c)); err != nil {
		t.Fatalf("c: %v", err)
	}
	// The same chain again changes nothing; the encoded chain round-trips.
	if added, err := tr.InstallChain(ch); err != nil || added != 0 {
		t.Fatalf("again: %d %v", added, err)
	}
	out, err := tr.ChainJSON()
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := roottrust.New(a.r, clk.now)
	if _, err := fresh.InstallChain(out); err != nil || fresh.Seq() != 2 {
		t.Fatalf("round trip: %v", err)
	}
}

func TestChainRefusesForgedBrokenReplayedAndRolledBackLinks(t *testing.T) {
	a, b, c, stranger := newRoot(t), newRoot(t), newRoot(t), newRoot(t)
	ab := link(t, a, b, 1, t0, day)
	bc := link(t, b, c, 2, t0, day)

	// A handover that names the pinned root but that a stranger signed.
	st, _ := roottrust.NewStatement(a.r, c.r, 1, t0, day)
	payload, _ := st.Payload()
	byStranger, _ := roottrust.SignSide(stranger.s, payload)
	byC, _ := roottrust.SignSide(c.s, payload)
	forged, _ := json.Marshal(roottrust.Bundle{Statement: payload, Old: byStranger, New: byC})

	cases := map[string]struct {
		ch   []byte
		want error
	}{
		"forged: signed by a non-root":          {chain(t, forged), roottrust.ErrBadHandover},
		"starts from a root that is not pinned": {chain(t, link(t, stranger, b, 1, t0, day)), roottrust.ErrNotCurrent},
		"missing link":                          {chain(t, bc), roottrust.ErrMissingLink},
		"sequence rollback":                     {chain(t, ab, link(t, b, c, 1, t0, day)), roottrust.ErrSequence},
		"sequence skips":                        {chain(t, ab, link(t, b, c, 3, t0, day)), roottrust.ErrMissingLink},
		"link out of order":                     {chain(t, ab, link(t, c, a, 2, t0, day)), roottrust.ErrNotCurrent},
		"issued before the link it follows":     {chain(t, ab, link(t, b, c, 2, t0.Add(-time.Hour), day)), roottrust.ErrBadStatement},
		"unknown chain version":                 {[]byte(`{"v":9,"handovers":[]}`), roottrust.ErrBadChain},
		"not json":                              {[]byte(`{`), roottrust.ErrBadChain},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tr, _ := roottrust.New(a.r, func() time.Time { return t0 })
			if _, err := tr.InstallChain(tc.ch); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tr.Seq() != 0 || len(tr.Accepted()) != 1 || tr.Current().KeyID != a.r.KeyID {
				t.Fatal("a refused chain must change nothing")
			}
		})
	}

	// A replayed older chain: the verifier holds a -> b -> c and is shown
	// a -> b only. It keeps what it holds.
	tr, _ := roottrust.New(a.r, func() time.Time { return t0 })
	if _, err := tr.InstallChain(chain(t, ab, bc)); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.InstallChain(chain(t, ab)); !errors.Is(err, roottrust.ErrOlderChain) {
		t.Fatalf("older chain: %v", err)
	}
	if tr.Seq() != 2 || tr.Current().KeyID != c.r.KeyID {
		t.Fatal("an older chain moved the head back")
	}
	// A different link at a sequence the verifier holds is a fork.
	if _, err := tr.InstallChain(chain(t, link(t, a, c, 1, t0, day))); !errors.Is(err, roottrust.ErrFork) {
		t.Fatalf("fork: %v", err)
	}
	// A single bundle follows the same rules.
	if _, err := tr.Apply(link(t, b, a, 2, t0, day)); !errors.Is(err, roottrust.ErrFork) {
		t.Fatalf("apply fork: %v", err)
	}
}

// Load is what every service calls: the pin, the chain file from the
// config, and an optional state file that keeps the highest chain.
func TestLoadTakesTheConfigChainAndKeepsTheHigherState(t *testing.T) {
	a, b, c := newRoot(t), newRoot(t), newRoot(t)
	ab := link(t, a, b, 1, t0, day)
	bc := link(t, b, c, 2, t0, day)
	dir := t.TempDir()
	state := filepath.Join(dir, "root-chain.state")
	var notes []string
	logf := func(f string, args ...any) { notes = append(notes, f) }
	now := func() time.Time { return t0 }

	// No chain: exactly the pinned root.
	tr, err := roottrust.Load(roottrust.Config{Pin: a.r, StatePath: state, Now: now, Logf: logf})
	if err != nil || tr.Seq() != 0 || len(tr.Accepted()) != 1 {
		t.Fatalf("no chain: %v", err)
	}
	tr, err = roottrust.Load(roottrust.Config{Pin: a.r, Chain: chain(t, ab, bc), StatePath: state, Now: now, Logf: logf})
	if err != nil || tr.Seq() != 2 {
		t.Fatalf("chain: %v", err)
	}
	// A restart with an older config chain keeps the state's chain.
	tr, err = roottrust.Load(roottrust.Config{Pin: a.r, Chain: chain(t, ab), StatePath: state, Now: now, Logf: logf})
	if err != nil || tr.Seq() != 2 || tr.Current().KeyID != c.r.KeyID {
		t.Fatalf("older config: %v", err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "older") {
		t.Fatalf("the older chain is not reported: %q", notes)
	}
	// A restart with no chain at all keeps it too.
	if tr, err = roottrust.Load(roottrust.Config{Pin: a.r, StatePath: state, Now: now}); err != nil || tr.Seq() != 2 {
		t.Fatalf("no config chain: %v", err)
	}
	// A fork in the config fails closed.
	if _, err := roottrust.Load(roottrust.Config{Pin: a.r, Chain: chain(t, link(t, a, c, 1, t0, day)), StatePath: state, Now: now}); !errors.Is(err, roottrust.ErrFork) {
		t.Fatalf("fork in config: %v", err)
	}
	// Without a state path the config chain is all there is.
	if tr, err = roottrust.Load(roottrust.Config{OneShot: true, Pin: a.r, Chain: chain(t, ab), Now: now}); err != nil || tr.Seq() != 1 {
		t.Fatalf("memory only: %v", err)
	}
	// The chain file sits beside the root public key file.
	pub := filepath.Join(dir, "root.pub")
	if got, err := roottrust.ReadChainBeside(pub); err != nil || got != nil {
		t.Fatalf("absent chain file: %q %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, roottrust.ChainFileName), chain(t, ab), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := roottrust.ReadChainBeside(pub); err != nil || len(got) == 0 {
		t.Fatalf("chain file: %v", err)
	}
}

// No document signed by a retired root counts after
// its overlap, stored or not. RootHealth tells a verifier, seven days
// ahead, that the set it holds must be re-signed by the new root, and the
// refusal names the runbook step.
func TestRootHealthWarnsBeforeTheOverlapEndsAndTheRefusalNamesTheRunbook(t *testing.T) {
	a, b, stranger := newRoot(t), newRoot(t), newRoot(t)
	clk := &clock{t0}
	tr, _ := roottrust.New(a.r, clk.now)
	byA := doc(t, a)
	if fp, until, soon, err := tr.RootHealth(byA); err != nil || fp != a.r.Fingerprint() || !until.IsZero() || soon {
		t.Fatalf("before a handover: %s %v %v %v", fp, until, soon, err)
	}
	if _, err := tr.InstallChain(chain(t, link(t, a, b, 1, t0, 30*day))); err != nil {
		t.Fatal(err)
	}
	if _, until, soon, err := tr.RootHealth(byA); err != nil || !until.Equal(t0.Add(30*day)) || soon {
		t.Fatalf("23 days and more before the end: %v %v %v", until, soon, err)
	}
	clk.t = t0.Add(23*day + time.Second)
	if _, _, soon, _ := tr.RootHealth(byA); !soon {
		t.Fatal("less than 7 days before the end: no warning")
	}
	if _, until, soon, err := tr.RootHealth(doc(t, b)); err != nil || !until.IsZero() || soon {
		t.Fatalf("the new root: %v %v %v", until, soon, err)
	}
	if _, _, _, err := tr.RootHealth(doc(t, stranger)); err == nil {
		t.Fatal("a stranger's document has a root")
	}
	clk.t = t0.Add(30 * day)
	_, err := tr.Verify(byA)
	if !errors.Is(err, roottrust.ErrRootExpired) || !strings.Contains(err.Error(), roottrust.RunbookStep) {
		t.Fatalf("the refusal must name the runbook step: %v", err)
	}
	if _, _, soon, err := tr.RootHealth(byA); err != nil || !soon {
		t.Fatalf("after the end: %v %v", soon, err)
	}
}

// PinKey makes a one-root trust from a parsed public key.
func TestPinKeyIsTheOneRootTrust(t *testing.T) {
	a, b := newRoot(t), newRoot(t)
	pub, err := a.s.Info().PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	r, err := roottrust.PinKey(pub, a.r.Alg)
	if err != nil {
		t.Fatal(err)
	}
	if r2, err := roottrust.PinKey(pub, ""); err != nil || r2.Alg != a.r.Alg {
		t.Fatalf("the algorithm from the key type: %v %v", r2.Alg, err)
	}
	tr, _ := roottrust.New(r, nil)
	if _, err := tr.Verify(doc(t, a)); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Verify(doc(t, b)); err == nil {
		t.Fatal("another root verified")
	}
}

func TestHandoverBundleAndPinDER(t *testing.T) {
	a, b := newRoot(t), newRoot(t)
	l, err := roottrust.HandoverBundle(a.s, b.s, 1, t0, day)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := roottrust.PinDER(a.r.Alg, a.r.PublicDER)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := roottrust.Load(roottrust.Config{OneShot: true, Pin: pin, Chain: chain(t, l), Now: func() time.Time { return t0 }})
	if err != nil || tr.Current().KeyID != b.r.KeyID {
		t.Fatalf("%v", err)
	}
	if _, err := roottrust.PinDER(a.r.Alg, []byte("junk")); err == nil {
		t.Fatal("junk DER pinned")
	}
}
