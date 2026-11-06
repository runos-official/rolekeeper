package applier_test

// 3.5 fresh start, 5.2 skip only what verified, and clock skew: the relay
// replaces "signed after the pod started" (two clocks) with a nonce that
// roid signs with the content digest.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
)

func TestRelayAFreshApplierPublishesItsNonceBeforeItReadsAnyBundle(t *testing.T) {
	r := newBareRelayRig(t)
	a := r.mk(t)
	if _, err := a.RunOnce(context.Background()); err == nil {
		t.Fatal("no bundle: want an error")
	}
	st := r.status(t) // written although there was no bundle to read
	if !st.NeedsFresh || len(st.FreshNonce) < 22 || len(st.FreshNonce) > 43 {
		t.Fatalf("status before any bundle: %+v", st)
	}
	again := r.mk(t)
	_, _ = again.RunOnce(context.Background())
	if st2 := r.status(t); st2.FreshNonce == st.FreshNonce {
		t.Fatal("two starts chose the same nonce")
	}
}

func TestRelayWithoutAFloorOnlyAFreshTokenForItsOwnNonceAndContentApplies(t *testing.T) {
	ctx := context.Background()
	r := newBareRelayRig(t)
	a := r.mk(t)
	_, _ = a.RunOnce(ctx)
	nonce := r.status(t).FreshNonce

	// The old envelope, no fresh token: nothing applies.
	old := r.publish(t, 1, "alice")
	if res, err := a.RunOnce(ctx); err == nil || res.Applied || r.bound("alice") {
		t.Fatalf("applied without a fresh token: %+v %v", res, err)
	}
	if st := r.status(t); !st.NeedsFresh || st.VerifyError != "fresh_required" {
		t.Fatalf("status: %+v", st)
	}
	// A fresh token for another nonce, and one for other content.
	r.write(t, old, r.freshFor(t, "BBBBBBBBBBBBBBBBBBBBBB", old))
	if res, err := a.RunOnce(ctx); err == nil || res.Applied {
		t.Fatalf("another nonce: %+v %v", res, err)
	}
	other := r.envelope(t, bundle.Bundle{Version: 1, Namespaces: []string{"apps"}, Objects: append(denyObjs(t, r.now), binding("mallory"))})
	r.write(t, old, r.freshFor(t, nonce, other)) // the token vouches for other content
	if res, err := a.RunOnce(ctx); err == nil || res.Applied || r.bound("alice") {
		t.Fatalf("a token for other content: %+v %v", res, err)
	}
	// An expired fresh token.
	stale := r.freshFor(t, nonce, old)
	r.now = r.now.Add(20 * time.Minute)
	r.write(t, old, stale)
	if res, err := a.RunOnce(ctx); err == nil || res.Applied {
		t.Fatalf("an expired fresh token: %+v %v", res, err)
	}
	// The right one.
	r.now = r.now.Add(time.Minute)
	fresh := r.envelope(t, bundle.Bundle{Version: 1, Namespaces: []string{"apps"}, Objects: append(denyObjs(t, r.now), binding("alice"))})
	r.write(t, fresh, r.freshFor(t, nonce, fresh))
	if res := mustPass(t, a); !res.Applied || !r.bound("alice") || r.floorVersion() != 1 {
		t.Fatalf("with the right token: %+v", res)
	}
	if st := r.status(t); st.NeedsFresh || st.FreshNonce != "" || st.VerifyError != "" {
		t.Fatalf("status after the first apply: %+v", st)
	}
}

// With a floor, a restart needs no fresh token (3.5, last paragraph).
func TestRelayARestartWithAFloorNeedsNoFreshToken(t *testing.T) {
	r := newBareRelayRig(t)
	a := r.mk(t)
	_, _ = a.RunOnce(context.Background())
	nonce := r.status(t).FreshNonce
	raw := r.publish(t, 1, "alice")
	r.write(t, raw, r.freshFor(t, nonce, raw))
	mustPass(t, a)

	r.now = r.now.Add(time.Minute)
	r.publish(t, 2, "alice", "bob") // no fresh token
	b := r.mk(t)
	if res := mustPass(t, b); !res.Applied || !r.bound("bob") {
		t.Fatalf("a restart with a floor: %+v", res)
	}
	if st := r.status(t); st.NeedsFresh {
		t.Fatalf("needs_fresh with a floor: %+v", st)
	}
}

// The attack of 12.5: delete the floor, restart, offer an old envelope with
// no fresh token. Nothing applies.
func TestRelayDeletingTheFloorAndRestartingDoesNotLetAnOldEnvelopeIn(t *testing.T) {
	ctx := context.Background()
	r := newBareRelayRig(t)
	a := r.mk(t)
	_, _ = a.RunOnce(ctx)
	nonce := r.status(t).FreshNonce
	raw := r.publish(t, 3, "alice")
	r.write(t, raw, r.freshFor(t, nonce, raw))
	mustPass(t, a)
	if r.floorVersion() != 3 {
		t.Fatal("fixture: no floor")
	}
	if err := os.Remove(r.floor.Path); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(time.Minute)
	b := r.mk(t)
	r.publish(t, 2, "alice", "mallory") // an older version, still inside its 15 minutes
	if res, err := b.RunOnce(ctx); err == nil || res.Applied || r.bound("mallory") {
		t.Fatalf("an old envelope applied after the floor was deleted: %+v %v", res, err)
	}
	if st := r.status(t); !st.NeedsFresh || st.VerifyError != "fresh_required" {
		t.Fatalf("status: %+v", st)
	}
}

// 12.2 skew. Inside the 30 s leeway everything applies. Outside it every
// envelope fails with the right class, and heals when the clock is fixed,
// because a failed envelope is read and verified again on every pass.
func TestRelayClockSkewFailsWithTheRightClassAndHeals(t *testing.T) {
	for _, tc := range []struct {
		skew time.Duration
		want string // "" applies
	}{
		{10 * time.Second, ""}, {-10 * time.Second, ""},
		{-2 * time.Minute, "not_yet_valid"}, {20 * time.Minute, "expired"},
	} {
		t.Run(tc.skew.String(), func(t *testing.T) {
			r := newRelayRig(t)
			r.skew = tc.skew
			// With a floor, so the fresh path is out of the way.
			_ = r.floor.Store(context.Background(), bundle.Floor{Version: 0, Digest: "x"})
			a := r.mk(t)
			r.publish(t, 1, "alice")
			res, err := a.RunOnce(context.Background())
			if tc.want == "" {
				if err != nil || !res.Applied {
					t.Fatalf("inside the leeway: %+v %v", res, err)
				}
				return
			}
			if err == nil || res.Applied {
				t.Fatalf("applied with a clock %s off: %+v", tc.skew, res)
			}
			if st := r.status(t); st.VerifyError != tc.want {
				t.Fatalf("verify_error %q, want %q", st.VerifyError, tc.want)
			}
			r.skew = 0 // time sync fixed; the envelope in the ConfigMap is unchanged
			if res := mustPass(t, a); !res.Applied || !r.bound("alice") {
				t.Fatalf("did not heal: %+v", res)
			}
			if st := r.status(t); st.VerifyError != "" {
				t.Fatalf("verify_error after the heal: %q", st.VerifyError)
			}
		})
	}
}

// 5.2: an applied envelope that is older than its 15 minutes does not flap,
// a newly delivered expired one is refused, a not-yet-valid one is taken
// when it becomes valid.
func TestRelaySkipOnlyWhatVerified(t *testing.T) {
	ctx := context.Background()
	r := newBareRelayRig(t)
	a := r.mk(t)
	_, _ = a.RunOnce(ctx)
	nonce := r.status(t).FreshNonce
	raw := r.publish(t, 1, "alice")
	r.write(t, raw, r.freshFor(t, nonce, raw))
	mustPass(t, a)

	// The clock moves 30 minutes. The envelope in the ConfigMap is the same.
	for range 3 {
		r.now = r.now.Add(10 * time.Minute)
		res, err := a.RunOnce(ctx)
		if err != nil || !res.Applied {
			t.Fatalf("an unchanged applied envelope flapped: %+v %v", res, err)
		}
	}
	if st := r.status(t); st.VerifyError != "" || !st.Status.Applied || st.BundleAgeS < 1700 {
		t.Fatalf("status after 30 minutes: %+v", st)
	}
	if !r.bound("alice") {
		t.Fatal("the binding went")
	}
	// A newly delivered expired envelope (the same old one, written again).
	r.write(t, raw, "")
	if _, err := a.RunOnce(ctx); err == nil || errors.Is(err, bundle.ErrStale) {
		t.Fatalf("an expired envelope delivered again: %v", err)
	}
	if st := r.status(t); st.VerifyError != "expired" {
		t.Fatalf("verify_error %q", st.VerifyError)
	}
	// A not-yet-valid one, accepted when its time comes.
	r.now = r.now.Add(time.Minute)
	r.skew = -3 * time.Minute
	r.publish(t, 2, "alice", "bob")
	if _, err := a.RunOnce(ctx); err == nil || r.bound("bob") {
		t.Fatalf("a not-yet-valid envelope: %v", err)
	}
	r.skew = 0
	if res := mustPass(t, a); !res.Applied || !r.bound("bob") {
		t.Fatalf("not accepted when valid: %+v", res)
	}
}
