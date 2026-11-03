package applier_test

// 5.6: what counts toward the 24 hour fail-safe in the relay. Exactly two
// inputs, both signed by roid and verified here: an unexpired signed
// refusal, and an unexpired envelope below the floor. Everything else the
// relay can do (silence, a missing bundle, junk, a stale token) neither
// counts nor resets.

import (
	"context"
	"testing"
	"time"
)

// failSafeRun drives the applier for total time in steps. before is called
// at the start of each step (the conductor's writes). It returns the time
// of the first fail-safe, or zero.
func failSafeRun(t *testing.T, r *relayRig, a *relayApplier, total, step time.Duration, before func()) time.Duration {
	t.Helper()
	start := r.now
	for r.now.Sub(start) < total {
		r.now = r.now.Add(step)
		before()
		res, _ := a.RunOnce(context.Background())
		if res.FailSafe {
			return r.now.Sub(start)
		}
	}
	return 0
}

func seeded(t *testing.T) (*relayRig, *relayApplier) {
	t.Helper()
	r := newBareRelayRig(t)
	a := r.mk(t)
	a.RefusedBound = 24 * time.Hour
	_, _ = a.RunOnce(context.Background())
	nonce := r.status(t).FreshNonce
	raw := r.publish(t, 5, "alice")
	r.write(t, raw, r.freshFor(t, nonce, raw))
	mustPass(t, a)
	if !r.bound("alice") {
		t.Fatal("fixture")
	}
	return r, a
}

func TestRelayAVerifiedSignedRefusalFor24HoursRemovesTheBindings(t *testing.T) {
	r, a := seeded(t)
	at := failSafeRun(t, r, a, 30*time.Hour, 10*time.Minute, func() { r.setRelay("", r.refusal(t, "cluster")) })
	if at < 24*time.Hour || at > 24*time.Hour+10*time.Minute {
		t.Fatalf("the fail-safe fired at %s, want 24 h", at)
	}
	if r.bound("alice") {
		t.Fatal("the binding stayed")
	}
	if st := r.status(t); !st.Status.FailSafe || !st.Status.Retired {
		t.Fatalf("status: %+v", st.Status)
	}
}

func TestRelayAMarkerThatIsNotAVerifiedUnexpiredRefusalNeverCounts(t *testing.T) {
	good := func(r *relayRig) string { return r.refusal(t, "cluster") }
	for name, marker := range map[string]func(r *relayRig) string{
		"unsigned text":   func(*relayRig) string { return "refused" },
		"an unsigned jwt": func(*relayRig) string { return "eyJhbGciOiJub25lIn0.e30." },
		"another cluster": func(r *relayRig) string {
			return r.mint(t, "k8s-rbac-refusal", "k8s-rbac-refusal:cluster", "acct-a", "cl-2", "")
		},
		"another account": func(r *relayRig) string {
			return r.mint(t, "k8s-rbac-refusal", "k8s-rbac-refusal:cluster", "acct-b", "cl-1", "")
		},
		"the bundle class": func(r *relayRig) string {
			return r.mint(t, "k8s-rbac-bundle", "k8s-rbac-refusal:cluster", "acct-a", "cl-1", "")
		},
		"a fresh token": func(r *relayRig) string {
			return r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "acct-a", "cl-1", "00")
		},
		"a signed refusal, never renewed (it expires)": func(r *relayRig) string { return "" },
	} {
		t.Run(name, func(t *testing.T) {
			r, a := seeded(t)
			once := good(r) // minted now, 15 minutes of life
			if at := failSafeRun(t, r, a, 72*time.Hour, 10*time.Minute, func() {
				if tok := marker(r); tok != "" {
					r.setRelay("", tok)
				} else {
					r.setRelay("", once)
				}
			}); at != 0 {
				t.Fatalf("fired at %s", at)
			}
			if !r.bound("alice") {
				t.Fatal("the binding went")
			}
		})
	}
}

// A delivered, verified envelope resets the run. A verify error, a silent
// conductor, a missing bundle and an outage neither count nor reset.
func TestRelayOnlyADeliveredVerifiedEnvelopeResetsTheRun(t *testing.T) {
	refuse := func(r *relayRig) func() { return func() { r.setRelay("", r.refusal(t, "cluster")) } }
	t.Run("a delivered envelope resets", func(t *testing.T) {
		r, a := seeded(t)
		if at := failSafeRun(t, r, a, 23*time.Hour, 10*time.Minute, refuse(r)); at != 0 {
			t.Fatalf("early: %s", at)
		}
		r.publish(t, 6, "alice") // roid serves the cluster after all
		r.setRelay("", "")
		mustPass(t, a)
		if at := failSafeRun(t, r, a, 23*time.Hour, 10*time.Minute, refuse(r)); at != 0 {
			t.Fatalf("the delivered envelope did not reset the run: fired at %s", at)
		}
	})
	t.Run("a verify error does not reset", func(t *testing.T) {
		r, a := seeded(t)
		if at := failSafeRun(t, r, a, 23*time.Hour, 10*time.Minute, refuse(r)); at != 0 {
			t.Fatalf("early: %s", at)
		}
		// Junk in the bundle ConfigMap, no refusal for two hours.
		r.setRelay("", "")
		r.rk.put("roid-rbac-bundle", map[string]string{"token": "junk"}, map[string][]byte{"body.gz": gzipOf(t, []byte(`{}`))})
		for range 12 {
			r.now = r.now.Add(10 * time.Minute)
			_, _ = a.RunOnce(context.Background())
		}
		r.setRelay("", r.refusal(t, "cluster"))
		r.now = r.now.Add(time.Minute)
		if res, _ := a.RunOnce(context.Background()); !res.FailSafe {
			t.Fatalf("a verify error reset the run: %+v", res)
		}
	})
	t.Run("silence between two refusals does not reset", func(t *testing.T) {
		r, a := seeded(t)
		if at := failSafeRun(t, r, a, 23*time.Hour, 10*time.Minute, refuse(r)); at != 0 {
			t.Fatalf("early: %s", at)
		}
		r.setRelay("", "") // the conductor stops writing; the cached envelope is not a delivery
		for range 12 {
			r.now = r.now.Add(10 * time.Minute)
			_, _ = a.RunOnce(context.Background())
		}
		r.setRelay("", r.refusal(t, "cluster"))
		r.now = r.now.Add(time.Minute)
		if res, _ := a.RunOnce(context.Background()); !res.FailSafe {
			t.Fatalf("silence reset the run: %+v", res)
		}
	})
	t.Run("a silent conductor, a missing bundle and an outage never fire", func(t *testing.T) {
		r, a := seeded(t)
		if at := failSafeRun(t, r, a, 48*time.Hour, 30*time.Minute, func() {}); at != 0 {
			t.Fatalf("a silent conductor fired at %s", at)
		}
		r.rk.drop("roid-rbac-bundle")
		if at := failSafeRun(t, r, a, 48*time.Hour, 30*time.Minute, func() {}); at != 0 {
			t.Fatalf("a missing bundle fired at %s", at)
		}
		r.rk.failGet["roid-rbac-bundle"] = errTest
		r.rk.failGet["roid-rbac-relay"] = errTest
		if at := failSafeRun(t, r, a, 48*time.Hour, 30*time.Minute, func() {}); at != 0 {
			t.Fatalf("an unreadable API server fired at %s", at)
		}
		if !r.bound("alice") {
			t.Fatal("the binding went")
		}
	})
}

// A verified, unexpired envelope below the floor counts. Roid signs
// one every few minutes for as long as it serves the cluster at an old
// version.
func TestRelayAVerifiedEnvelopeBelowTheFloorCounts(t *testing.T) {
	r, a := seeded(t)
	at := failSafeRun(t, r, a, 30*time.Hour, 10*time.Minute, func() { r.publish(t, 3, "alice", "mallory") })
	if at < 24*time.Hour || at > 24*time.Hour+10*time.Minute {
		t.Fatalf("fired at %s", at)
	}
	if r.bound("mallory") {
		t.Fatal("the stale bundle applied")
	}
}

// A below-floor envelope that has expired counts for nothing: a replay of
// an old signed envelope cannot keep the run going or start it.
func TestRelayAnExpiredBelowFloorEnvelopeNeverCounts(t *testing.T) {
	r, a := seeded(t)
	r.publish(t, 3, "alice", "mallory") // written once, never renewed
	if at := failSafeRun(t, r, a, 72*time.Hour, 10*time.Minute, func() {}); at != 0 {
		t.Fatalf("fired at %s", at)
	}
}
