package roottrust_test

import (
	"errors"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer/roottrust"
)

// The minimum chain sequence is baked into the build (roottrust.Floors,
// by pin), where neither a database writer nor a ConfigMap writer reaches.
// A verifier whose chain is below it does not start, whatever its config
// and state say.
func TestTheBakedFloorRefusesAnOlderChain(t *testing.T) {
	a, b, c := newRoot(t), newRoot(t), newRoot(t)
	ab, bc := link(t, a, b, 1, t0, day), link(t, b, c, 2, t0.Add(time.Hour), day)
	restore := roottrust.SetFloorForTest(a.r.Fingerprint(), 2)
	t.Cleanup(restore)
	now := func() time.Time { return t0.Add(2 * time.Hour) }
	if _, err := roottrust.Load(roottrust.Config{OneShot: true, Pin: a.r, Chain: chain(t, ab), Now: now}); !errors.Is(err, roottrust.ErrBelowFloor) {
		t.Fatalf("an older chain: %v", err)
	}
	if _, err := roottrust.Load(roottrust.Config{OneShot: true, Pin: a.r, Now: now}); !errors.Is(err, roottrust.ErrBelowFloor) {
		t.Fatalf("no chain at all: %v", err)
	}
	if _, err := roottrust.Load(roottrust.Config{OneShot: true, Pin: a.r, Chain: chain(t, ab, bc), Now: now}); err != nil {
		t.Fatalf("a chain at the floor: %v", err)
	}
	// A caller that adds links after Load (roid, from root_chain) defers the
	// check and makes it itself.
	tr, err := roottrust.Load(roottrust.Config{OneShot: true, DeferFloor: true, Pin: a.r, Chain: chain(t, ab), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.CheckFloor(); !errors.Is(err, roottrust.ErrBelowFloor) {
		t.Fatalf("deferred check: %v", err)
	}
	if _, err := tr.Apply(bc); err != nil {
		t.Fatal(err)
	}
	if err := tr.CheckFloor(); err != nil {
		t.Fatalf("after the link: %v", err)
	}
	// Another pin has its own floor (none here).
	if _, err := roottrust.Load(roottrust.Config{OneShot: true, Pin: c.r, Now: now}); err != nil {
		t.Fatalf("another pin: %v", err)
	}
}
