package keys_test

// Reproductions of attacks on the key sets,
// written as tests that pass only when the
// attack is refused.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
	"github.com/runos-official/rolekeeper/signer/keys"
)

func attackerKey(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, must(x509.MarshalPKIXPublicKey(pub))
}

func leafSigned(t *testing.T, s *signer.Signer, d keys.Doc) string {
	t.Helper()
	raw := must(json.Marshal(d))
	return must(jws.Sign(s, keys.DocType, raw))
}

// A stolen leaf key cannot publish a sibling key.
func TestLeafSignedDocCannotAddSibling(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	stolen := must(f.m.ActiveSigner(f.ctx, p))
	_, der := attackerKey(t)
	d := f.m.Doc(p)
	d.Version++
	d.Keys = append(d.Keys, keys.PublishedKey{Kid: "gate-attacker", Alg: signer.AlgEdDSA, State: keys.StateNext, PublicDER: der, PublishedAt: f.clk.now()})
	if err := v.Update(leafSigned(t, stolen, d)); !errors.Is(err, keys.ErrRootRequired) {
		t.Fatalf("leaf-signed sibling add: want ErrRootRequired, got %v", err)
	}
	if _, _, err := v.Lookup("gate-attacker"); !errors.Is(err, keys.ErrUnknownKey) {
		t.Fatalf("attacker kid visible: %v", err)
	}
}

// A stolen leaf key cannot write Removed, so the root reset works.
func TestLeafCannotPoisonRootReset(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	stolen := must(f.m.ActiveSigner(f.ctx, p))
	d := f.m.Doc(p)
	var standby string
	for _, k := range d.Keys {
		if k.State == keys.StateNext {
			standby = k.Kid
		}
	}
	poison := d
	poison.Version++
	poison.Removed = []string{standby}
	if err := v.Update(leafSigned(t, stolen, poison)); !errors.Is(err, keys.ErrRootRequired) {
		t.Fatalf("leaf-signed poison: want ErrRootRequired, got %v", err)
	}
	if err := v.Update(must(f.m.Compromise(f.ctx, p, stolen.KeyID(), f.root))); err != nil {
		t.Fatalf("root reset refused: %v", err)
	}
	if _, _, err := v.Lookup(standby); err != nil {
		t.Fatalf("promoted standby unknown after reset: %v", err)
	}
}

// A stolen leaf key cannot freeze the version.
func TestLeafCannotFreezeVersion(t *testing.T) {
	f := setup(t)
	p := signer.PurposeKubernetesIssuer
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	stolen := must(f.m.ActiveSigner(f.ctx, p))
	d := f.m.Doc(p)
	d.Version = math.MaxUint64
	if err := v.Update(leafSigned(t, stolen, d)); !errors.Is(err, keys.ErrRootRequired) {
		t.Fatalf("leaf-signed MaxUint64: want ErrRootRequired, got %v", err)
	}
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(must(f.m.Publish(f.ctx, p, f.root))); err != nil {
		t.Fatalf("root ceremony after rotation refused: %v", err)
	}
}

// Routine rotation promotes the standby with no new root signature, and
// the next standby is unusable until a root ceremony publishes it and the
// publish lead has run.
func TestRoutineRotationNeedsNoRootSignatureAndStandbyNeedsCeremony(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	v := f.view(t, p, pinned)
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	s := must(f.m.ActiveSigner(f.ctx, p))
	if _, _, err := v.Lookup(s.KeyID()); err != nil {
		t.Fatalf("promoted standby unknown to a verifier that saw no update: %v", err)
	}
	// The new standby is not root-published yet: it cannot be activated.
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Activate(f.ctx, p); !errors.Is(err, keys.ErrNotRootPublished) {
		t.Fatalf("activate unpublished standby: want ErrNotRootPublished, got %v", err)
	}
	if err := v.Update(must(f.m.Publish(f.ctx, p, f.root))); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Activate(f.ctx, p); !errors.Is(err, keys.ErrPublishLeadNotMet) {
		t.Fatalf("activate right after ceremony: want ErrPublishLeadNotMet, got %v", err)
	}
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Activate(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	s2 := must(f.m.ActiveSigner(f.ctx, p))
	if _, _, err := v.Lookup(s2.KeyID()); err != nil {
		t.Fatalf("ceremony standby unknown: %v", err)
	}
	// Every root-signed set holds the active key and one standby.
	if _, err := f.m.Publish(f.ctx, p, f.root); !errors.Is(err, keys.ErrNoNext) {
		t.Fatalf("ceremony with no standby: want ErrNoNext, got %v", err)
	}
	// A leaf-key Publish is refused.
	if _, err := f.m.Publish(f.ctx, p, s2); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Fatalf("leaf ceremony: want ErrWrongPurpose, got %v", err)
	}
}

// A durable view keeps the reset across a restart.
func TestDurableViewRestartKeepsReset(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	bad := pinned.Active().Kid
	path := filepath.Join(t.TempDir(), "gate.keyset")
	v := must(keys.NewViewWithState(p, f.root.Public(), f.rootAlg, pinned, path))
	reset := must(f.m.Compromise(f.ctx, p, bad, f.root))
	if err := v.Update(reset); err != nil {
		t.Fatal(err)
	}
	// Restart from the install pin plus the state file.
	v2 := must(keys.NewViewWithState(p, f.root.Public(), f.rootAlg, pinned, path))
	if _, _, err := v2.Lookup(bad); !errors.Is(err, keys.ErrKeyRemoved) {
		t.Fatalf("restarted view trusts the compromised key: %v", err)
	}
	if err := v2.Update(reset); !errors.Is(err, keys.ErrNoChange) && !errors.Is(err, keys.ErrRollback) {
		t.Fatalf("replayed reset after restart: %v", err)
	}
	// A tampered state file fails closed.
	if err := writeFile(path, []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.NewViewWithState(p, f.root.Public(), f.rootAlg, pinned, path); err == nil {
		t.Fatal("tampered state file accepted")
	}
	_ = time.Second
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }
