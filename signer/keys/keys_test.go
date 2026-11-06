package keys_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/revlog"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock                   { return &clock{t: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)} }

// must panics on error; a panic fails the test with a stack trace.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type fixture struct {
	ctx     context.Context
	clk     *clock
	b       *signer.SoftBackend
	log     *revlog.Log
	m       *keys.Manager
	root    *signer.Signer
	rootAlg signer.Algorithm
}

func setup(t testing.TB) *fixture {
	t.Helper()
	ctx := context.Background()
	clk := newClock()
	b := signer.NewSoftBackend()
	l := must(revlog.Open(filepath.Join(t.TempDir(), "rev.log")))
	t.Cleanup(func() { l.Close() })
	l.Now = clk.now
	off := signer.NewOfflineRootBackend()
	rk := must(off.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA))
	root := must(signer.New(ctx, off, rk.ID, signer.PurposeKeySetRoot))
	return &fixture{ctx: ctx, clk: clk, b: b, log: l, m: keys.NewManager(b, l, clk.now), root: root, rootAlg: signer.AlgEdDSA}
}

func (f *fixture) view(t testing.TB, p signer.Purpose, pinned keys.Doc) *keys.View {
	t.Helper()
	return must(keys.NewView(p, f.root.Public(), f.rootAlg, pinned))
}

func TestBootstrapPublishesActiveAndStandby(t *testing.T) {
	f := setup(t)
	d := must(f.m.Bootstrap(f.ctx, signer.PurposeKubernetesIssuer, signer.AlgEdDSA))
	var active, next int
	for _, k := range d.Keys {
		switch k.State {
		case keys.StateActive:
			active++
		case keys.StateNext:
			next++
		}
	}
	if active != 1 || next != 1 {
		t.Fatalf("want one active and one standby next key, got %+v", d.Keys)
	}
	if _, err := f.m.Bootstrap(f.ctx, signer.PurposeKubernetesIssuer, signer.AlgEdDSA); err == nil {
		t.Fatal("second bootstrap must fail")
	}
}

func TestActivateRefusedBeforePublishLead(t *testing.T) {
	f := setup(t)
	p := signer.PurposeVPNLease
	must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	f.clk.advance(p.RotationOverlap() - time.Second)
	if err := f.m.Activate(f.ctx, p); !errors.Is(err, keys.ErrPublishLeadNotMet) {
		t.Fatalf("want ErrPublishLeadNotMet, got %v", err)
	}
	f.clk.advance(time.Second)
	if err := f.m.Activate(f.ctx, p); err != nil {
		t.Fatal(err)
	}
}

func TestRetiredKeyStaysPublishedForOverlapThenRemoved(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	d0 := must(f.m.Bootstrap(f.ctx, p, signer.AlgES256))
	old := d0.Active().Kid
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgES256); err != nil {
		t.Fatal(err)
	}
	f.clk.advance(p.RotationOverlap() - time.Second)
	if gone := must(f.m.RetireExpired(f.ctx, p)); len(gone) != 0 {
		t.Fatalf("retired too early: %v", gone)
	}
	f.clk.advance(time.Second)
	gone := must(f.m.RetireExpired(f.ctx, p))
	if len(gone) != 1 || gone[0] != old {
		t.Fatalf("want %s retired, got %v", old, gone)
	}
	if f.m.Doc(p).Find(old) != nil {
		t.Fatal("retired key still published")
	}
	if _, err := f.b.Sign(f.ctx, signer.SignRequest{KeyID: old, Purpose: p, Digest: make([]byte, 32), Hash: crypto.SHA256}); !errors.Is(err, signer.ErrKeyDisabled) {
		t.Fatalf("retired key must be disabled in custody, got %v", err)
	}
}

func TestAgentCANeverRotates(t *testing.T) {
	f := setup(t)
	d := must(f.m.Bootstrap(f.ctx, signer.PurposeAgentCA, signer.AlgES256))
	if len(d.Keys) != 1 {
		t.Fatalf("agent-ca gets no standby key, got %d keys", len(d.Keys))
	}
	if _, err := f.m.PublishNext(f.ctx, signer.PurposeAgentCA, signer.AlgES256); !errors.Is(err, keys.ErrRotationForbidden) {
		t.Fatalf("want ErrRotationForbidden, got %v", err)
	}
}

// Tokens issued every minute for 30 simulated hours
// across many rotations; every unexpired token verifies at every minute
// through a verifier that pulls the key set every 5 minutes.
func TestRotationCausesNoFailedVerification(t *testing.T) {
	f := setup(t)
	p := signer.PurposeKubernetesIssuer
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	type tok struct {
		c   string
		exp time.Time
	}
	var live []tok
	rotations, checks := 0, 0
	latest := "" // the last root-signed set: verifiers pull it
	for minute := 0; minute < 30*60; minute++ {
		if minute%5 == 0 && latest != "" {
			if err := v.Update(latest); err != nil && !errors.Is(err, keys.ErrNoChange) {
				t.Fatalf("minute %d: view update: %v", minute, err)
			}
		}
		if err := f.m.Rotate(f.ctx, p, signer.AlgEdDSA); err == nil {
			rotations++
			// The ceremony that publishes the new standby.
			latest = must(f.m.Publish(f.ctx, p, f.root))
		} else if !errors.Is(err, keys.ErrPublishLeadNotMet) {
			t.Fatal(err)
		}
		if _, err := f.m.RetireExpired(f.ctx, p); err != nil {
			t.Fatal(err)
		}
		s := must(f.m.ActiveSigner(f.ctx, p))
		c := must(jws.Sign(s, p.TokenType(), []byte(fmt.Sprintf(`{"m":%d}`, minute))))
		live = append(live, tok{c: c, exp: f.clk.now().Add(p.MaxTokenLifetime())})
		kept := live[:0]
		for _, x := range live {
			if !f.clk.now().Before(x.exp) {
				continue
			}
			h := must(jws.PeekHeader(x.c))
			pub, alg, err := v.Lookup(h.Kid)
			if err != nil {
				t.Fatalf("minute %d: lookup %s: %v", minute, h.Kid, err)
			}
			if _, err := jws.Verify(x.c, pub, alg); err != nil {
				t.Fatalf("minute %d: verify: %v", minute, err)
			}
			checks++
			kept = append(kept, x)
		}
		live = kept
		f.clk.advance(time.Minute)
	}
	if rotations < 10 {
		t.Fatalf("only %d rotations, the test did not exercise rotation", rotations)
	}
	t.Logf("rotations=%d verifications=%d failures=0", rotations, checks)
}

// A compromised key is removed by a key-set reset signed by the
// offline root. The standby key takes over with no verifier outage.
func TestCompromisedKeyRemovedByRootSignedReset(t *testing.T) {
	f := setup(t)
	p := signer.PurposeVPNLease
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	bad := pinned.Active().Kid
	badSigner := must(signer.New(f.ctx, f.b, bad, p))
	preDoc := must(f.m.Publish(f.ctx, p, f.root)) // a root-signed set from before the reset
	oldTok := must(jws.Sign(badSigner, p.TokenType(), []byte(`{}`)))

	reset := must(f.m.Compromise(f.ctx, p, bad, f.root))
	if err := v.Update(reset); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Lookup(bad); !errors.Is(err, keys.ErrKeyRemoved) {
		t.Fatalf("compromised key: want ErrKeyRemoved, got %v", err)
	}
	h := must(jws.PeekHeader(oldTok))
	if _, _, err := v.Lookup(h.Kid); !errors.Is(err, keys.ErrKeyRemoved) {
		t.Fatal("token signed by the compromised key must be refused")
	}
	// New tokens use the promoted standby, which the verifier already has.
	s := must(f.m.ActiveSigner(f.ctx, p))
	if s.KeyID() == bad {
		t.Fatal("still signing with the compromised key")
	}
	if _, _, err := v.Lookup(s.KeyID()); err != nil {
		t.Fatalf("replacement key unknown to verifier: %v", err)
	}
	// Custody refuses the compromised key.
	if _, err := badSigner.Sign(nil, []byte("x"), nil); !errors.Is(err, signer.ErrKeyDisabled) {
		t.Fatalf("custody must disable the key, got %v", err)
	}
	// Old documents cannot roll the removal back: the pre-reset set has a
	// lower epoch, and a leaf-signed set is never accepted.
	if err := v.Update(preDoc); !errors.Is(err, keys.ErrRollback) {
		t.Fatalf("pre-reset doc: want ErrRollback, got %v", err)
	}
	if err := v.Update(must(f.m.LegacyLeafSignedDoc(f.ctx, p))); !errors.Is(err, keys.ErrRootRequired) {
		t.Fatalf("leaf-signed doc: want ErrRootRequired, got %v", err)
	}
	if err := v.Update(reset); !errors.Is(err, keys.ErrNoChange) {
		t.Fatalf("replayed reset: want ErrNoChange (no install), got %v", err)
	}
	// The audit stand-in: a key.compromised entry in the external log.
	var found bool
	for _, e := range f.log.Since(0) {
		if e.Kind == revlog.KindKeyCompromised && e.Subject == bad {
			found = true
		}
	}
	if !found {
		t.Fatal("no key.compromised entry in the revocation log")
	}
}

func TestOnlineKeyCannotForgeRootReset(t *testing.T) {
	f := setup(t)
	p := signer.PurposeVPNLease
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	// An attacker with an online key of another purpose mints a "root" doc.
	other := must(f.b.CreateKey(f.ctx, signer.PurposeGate, signer.AlgEdDSA))
	os := must(signer.New(f.ctx, f.b, other.ID, signer.PurposeGate))
	d := pinned
	d.Epoch++
	d.Keys = nil
	raw, _ := json.Marshal(d)
	forged := must(jws.Sign(os, keys.DocType, raw))
	if err := v.Update(forged); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Fatalf("gate-signed key-set doc for vpn view: want ErrWrongPurpose, got %v", err)
	}
}

// A stolen online
// key cannot publish a sibling key at all, because a View accepts only
// root-signed sets. The root reset still removes the stolen key.
func TestCompromisedKeySiblingDoesNotSurviveRootReset(t *testing.T) {
	f := setup(t)
	p := signer.PurposeKubernetesIssuer
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	bad := pinned.Active().Kid
	stolen := must(signer.New(f.ctx, f.b, bad, p))
	atk := signer.NewSoftBackend()
	ak := must(atk.CreateKey(f.ctx, p, signer.AlgEdDSA))
	d := pinned
	d.Version = 1 << 40
	d.Keys = append(append([]keys.PublishedKey{}, d.Keys...), keys.PublishedKey{Kid: ak.ID, Alg: ak.Algorithm, State: keys.StateActive, PublicDER: ak.PublicDER})
	raw, _ := json.Marshal(d)
	if err := v.Update(must(jws.Sign(stolen, keys.DocType, raw))); !errors.Is(err, keys.ErrRootRequired) {
		t.Fatalf("leaf-signed sibling doc: want ErrRootRequired, got %v", err)
	}
	if _, _, err := v.Lookup(ak.ID); !errors.Is(err, keys.ErrUnknownKey) {
		t.Fatal("sibling must never be visible")
	}
	if err := v.Update(must(f.m.Compromise(f.ctx, p, bad, f.root))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Lookup(ak.ID); !errors.Is(err, keys.ErrUnknownKey) {
		t.Fatalf("sibling survived the root reset: %v", err)
	}
	// The next root ceremony is accepted.
	if err := v.Update(must(f.m.Publish(f.ctx, p, f.root))); err != nil {
		t.Fatalf("post-reset ceremony: %v", err)
	}
}

func TestViewRefusesRoutineDocOfAnotherPurpose(t *testing.T) {
	f := setup(t)
	k8s := must(f.m.Bootstrap(f.ctx, signer.PurposeKubernetesIssuer, signer.AlgEdDSA))
	must(f.m.Bootstrap(f.ctx, signer.PurposeVPNLease, signer.AlgEdDSA))
	v := f.view(t, signer.PurposeKubernetesIssuer, k8s)
	if err := v.Update(must(f.m.LegacyLeafSignedDoc(f.ctx, signer.PurposeVPNLease))); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Fatalf("want ErrWrongPurpose, got %v", err)
	}
	if _, err := keys.NewView(signer.PurposeVPNLease, f.root.Public(), f.rootAlg, k8s); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Fatalf("pinning a doc of another purpose: %v", err)
	}
}

func TestJWKSPerPurposeHasDistinctPublicKeysOnly(t *testing.T) {
	f := setup(t)
	seen := map[string]signer.Purpose{}
	for _, p := range signer.AllPurposes() {
		d := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
		set := f.view(t, p, d).JWKS()
		for _, k := range set.Keys {
			if !k.IsPublic() {
				t.Fatalf("%s JWKS holds a private key", p)
			}
			if q, dup := seen[k.KeyID]; dup {
				t.Fatalf("kid %s in both %s and %s", k.KeyID, q, p)
			}
			seen[k.KeyID] = p
		}
	}
}

// A restored key set refuses to sign
// until it replays the external revocation log.
func TestRestoredKeySetRefusesToSignUntilReplay(t *testing.T) {
	f := setup(t)
	p := signer.PurposeOperationGrant
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgES256))
	v := f.view(t, p, pinned)
	snap := f.m.Snapshot() // the T0 backup
	bad := pinned.Active().Kid
	if err := v.Update(must(f.m.Compromise(f.ctx, p, bad, f.root))); err != nil {
		t.Fatal(err)
	}

	r := keys.RestoreManager(f.b, f.log, f.clk.now, snap)
	if _, err := r.ActiveSigner(f.ctx, p); !errors.Is(err, revlog.ErrReplayRequired) {
		t.Fatalf("restored manager signed without replay: %v", err)
	}
	if _, err := r.LegacyLeafSignedDoc(f.ctx, p); !errors.Is(err, revlog.ErrReplayRequired) {
		t.Fatalf("restored manager published without replay: %v", err)
	}
	if _, err := r.PublishNext(f.ctx, p, signer.AlgES256); !errors.Is(err, revlog.ErrReplayRequired) {
		t.Fatalf("restored manager rotated without replay: %v", err)
	}
	if err := r.Replay(f.log.Since(snap.Watermark)); err != nil {
		t.Fatal(err)
	}
	s := must(r.ActiveSigner(f.ctx, p))
	if s.KeyID() == bad {
		t.Fatal("replayed manager signs with the compromised key")
	}
	if r.Doc(p).Find(bad) != nil {
		t.Fatal("compromised key is back in the published set")
	}
	// The verifier does not see a rollback after restore + replay.
	f.clk.advance(p.RotationOverlap())
	if err := r.Rotate(f.ctx, p, signer.AlgES256); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(must(r.Publish(f.ctx, p, f.root))); err != nil {
		t.Fatalf("post-restore doc refused by verifier: %v", err)
	}
}

// Without replay, a restored manager would roll the key-set version back.
func TestReplayKeepsKeySetVersionMonotonic(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	snap := f.m.Snapshot()
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(must(f.m.Publish(f.ctx, p, f.root))); err != nil {
		t.Fatal(err)
	}
	r := keys.RestoreManager(f.b, f.log, f.clk.now, snap)
	if err := r.Replay(f.log.Since(snap.Watermark)); err != nil {
		t.Fatal(err)
	}
	if r.Doc(p).Version != f.m.Doc(p).Version {
		t.Fatalf("version after replay %d, live %d", r.Doc(p).Version, f.m.Doc(p).Version)
	}
	if err := v.Update(must(r.Publish(f.ctx, p, f.root))); err != nil {
		t.Fatalf("replayed manager's next ceremony: %v", err)
	}
}
