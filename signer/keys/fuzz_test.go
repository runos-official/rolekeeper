package keys_test

import (
	"testing"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
)

// Update never panics, and a document it accepts leaves the view exactly
// as the genuine root-signed set does.
func FuzzViewUpdate(f *testing.F) {
	fx := setup(f)
	p := signer.PurposeGate
	pinned := must(fx.m.Bootstrap(fx.ctx, p, signer.AlgEdDSA))
	pub := must(fx.m.Publish(fx.ctx, p, fx.root))
	ref := fx.view(f, p, pinned)
	if err := ref.Update(pub); err != nil {
		f.Fatal(err)
	}
	wantV, wantSub := ref.Version()
	f.Add(pub)
	f.Add(pub + "x")
	f.Add("")
	f.Fuzz(func(t *testing.T, doc string) {
		v, err := keys.NewView(p, fx.root.Public(), fx.rootAlg, pinned)
		if err != nil {
			t.Fatal(err)
		}
		if v.Update(doc) != nil {
			return
		}
		if gotV, gotSub := v.Version(); gotV != wantV || gotSub != wantSub {
			t.Fatalf("accepted a document that sets version %d.%d, want %d.%d", gotV, gotSub, wantV, wantSub)
		}
	})
}
