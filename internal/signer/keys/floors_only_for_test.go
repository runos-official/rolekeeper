package keys_test

import (
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer"
)

// The install pin may carry the floor of one account only. A
// verifier pinned that way and a verifier pinned with every floor (an
// earlier install) both follow the same root-signed set, and neither floor
// goes down. The root-signed set holds no floor table, so a raise
// after the pin reaches a verifier through the lists, not through the set.
func TestFloorsOnlyForPinAndFullPinFollowTheSameRootSignedSet(t *testing.T) {
	f := setup(t)
	p := signer.PurposeEmergencyRoster
	must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	for acct, v := range map[string]uint64{"acct-1": 3, "acct-2": 5} {
		if err := f.m.SetMinVersion(p, acct, v); err != nil {
			t.Fatal(err)
		}
	}
	full := f.m.Doc(p)
	scoped := full.FloorsOnlyFor("acct-1")
	if len(scoped.MinVersions) != 1 || scoped.MinVersion("acct-1") != 3 {
		t.Fatalf("scoped floors: %v", scoped.MinVersions)
	}
	if len(full.MinVersions) != 2 {
		t.Fatalf("the copy changed the source: %v", full.MinVersions)
	}
	if got := full.FloorsOnlyFor("acct-none"); len(got.MinVersions) != 0 {
		t.Fatalf("a subject with no floor: %v", got.MinVersions)
	}
	vFull, vScoped := f.view(t, p, full), f.view(t, p, scoped)
	if err := f.m.SetMinVersion(p, "acct-1", 4); err != nil {
		t.Fatal(err)
	}
	signed := must(f.m.Publish(f.ctx, p, f.root))
	for name, v := range map[string]interface {
		Update(string) error
		MinVersion(string) uint64
	}{"full pin": vFull, "scoped pin": vScoped} {
		if err := v.Update(signed); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := v.MinVersion("acct-1"); got != 3 {
			t.Errorf("%s: floor of acct-1 is %d, want the pin's 3 (the set carries no floor)", name, got)
		}
	}
}
