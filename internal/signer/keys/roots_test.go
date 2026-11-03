package keys_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
)

// A view built over a root trust list takes a key set from a pinned root, and
// its durable state is checked against the same list at restart.
func TestViewOverRootTrustAcceptsAPinnedRootAndRestartsFromState(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	f.clk.advance(p.RotationOverlap())
	must1(f.m.Rotate(f.ctx, p, signer.AlgEdDSA))
	signed := must(f.m.Publish(f.ctx, p, f.root))

	pin := roottrust.Root{KeyID: f.root.KeyID(), Alg: signer.AlgEdDSA, PublicDER: f.root.Info().PublicDER}
	tr := must(roottrust.New(pin, f.clk.now))
	state := filepath.Join(t.TempDir(), "view")
	v := must(keys.NewViewRoots(p, tr, pinned, state))
	if err := v.Update(signed); err != nil {
		t.Fatal(err)
	}
	again := must(keys.NewViewRoots(p, tr, pinned, state))
	if e, ver := again.Version(); ver == 0 || e == 0 {
		t.Fatalf("the restart lost the set: %d %d", e, ver)
	}
	// A root that is not on the list does not sign a set.
	other := setup(t)
	otherSigned := must(func() (string, error) {
		pin2 := must(other.m.Bootstrap(other.ctx, p, signer.AlgEdDSA))
		_ = pin2
		other.clk.advance(p.RotationOverlap())
		must1(other.m.Rotate(other.ctx, p, signer.AlgEdDSA))
		return other.m.Publish(other.ctx, p, other.root)
	}())
	fresh := must(keys.NewViewRoots(p, tr, pinned, filepath.Join(t.TempDir(), "v2")))
	if err := fresh.Update(otherSigned); err == nil {
		t.Fatal("a set signed by a root that is not trusted was accepted")
	}
	if _, err := keys.NewViewRoots(p, nil, pinned, state); !errors.Is(err, keys.ErrState) {
		t.Fatalf("no root list: %v", err)
	}
}

func must1(err error) {
	if err != nil {
		panic(err)
	}
}
