package keys_test

import (
	"testing"

	"github.com/runos-official/rolekeeper/signer"
)

// BumpVersion moves the version of a set by one and
// changes nothing else, so a request for the next version is a new request
// when an earlier one was signed and lost. It needs no root signature, like
// every step that moves the version without changing what the root signs.
func TestBumpVersionMovesOnlyTheVersion(t *testing.T) {
	f := setup(t)
	p := signer.PurposeEmergencyRoster
	must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	if err := f.m.SetMinVersion(p, "acct-1", 3); err != nil {
		t.Fatal(err)
	}
	before := f.m.Doc(p)
	if err := f.m.BumpVersion(p); err != nil {
		t.Fatal(err)
	}
	after := f.m.Doc(p)
	if after.Version != before.Version+1 || after.Epoch != before.Epoch {
		t.Fatalf("version %d -> %d, epoch %d -> %d", before.Version, after.Version, before.Epoch, after.Epoch)
	}
	if len(after.Keys) != len(before.Keys) || after.MinVersion("acct-1") != 3 || len(after.Removed) != len(before.Removed) {
		t.Fatalf("the bump changed more than the version: %+v", after)
	}
	for i, k := range after.Keys {
		if k.Kid != before.Keys[i].Kid || k.State != before.Keys[i].State {
			t.Fatalf("key %d changed", i)
		}
	}
	// The next request is for the version above the bump.
	req := must(f.m.PreparePublish(f.ctx, p))
	if req.Doc.Version != after.Version+1 {
		t.Fatalf("request version %d, want %d", req.Doc.Version, after.Version+1)
	}
	if err := f.m.BumpVersion(signer.PurposeGate); err == nil {
		t.Fatal("a bump of a purpose with no set")
	}
}
