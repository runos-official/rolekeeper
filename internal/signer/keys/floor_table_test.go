package keys_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
)

// The root-signed set holds keys only. roid keeps its
// live floors in the Manager, and a verifier keeps its floor locally.

func floorFixture(t *testing.T) (*fixture, signer.Purpose) {
	t.Helper()
	f := setup(t)
	p := signer.PurposeEmergencyRoster
	must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	for acct, v := range map[string]uint64{"acct-1": 3, "acct-2": 5} {
		if err := f.m.SetMinVersion(p, acct, v); err != nil {
			t.Fatal(err)
		}
	}
	return f, p
}

func payloadOf(t *testing.T, signed string) (keys.Doc, string) {
	t.Helper()
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", signed)
	}
	raw := must(base64.RawURLEncoding.DecodeString(parts[1]))
	var d keys.Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d, string(raw)
}

func TestSignedSetsHoldNoFloorTable(t *testing.T) {
	f, p := floorFixture(t)
	signed := must(f.m.Publish(f.ctx, p, f.root))
	d, raw := payloadOf(t, signed)
	if len(d.MinVersions) != 0 || strings.Contains(raw, "acct-") || strings.Contains(raw, "min_versions") {
		t.Fatalf("the published set names accounts or holds a table: %s", raw)
	}
	// roid keeps its live floors.
	if got := f.m.Doc(p).MinVersion("acct-2"); got != 5 {
		t.Fatalf("the manager lost its floor: %d", got)
	}
	if got := f.m.LastSigned(p); got != signed {
		t.Fatal("last signed is not the published set")
	}
	// A compromise reset is signed in the same form.
	reset := must(f.m.Compromise(f.ctx, p, f.m.Doc(p).Active().Kid, f.root))
	if _, raw := payloadOf(t, reset); strings.Contains(raw, "acct-") || strings.Contains(raw, "min_versions") {
		t.Fatalf("the reset names accounts: %s", raw)
	}
	if got := f.m.Doc(p).MinVersion("acct-1"); got != 3 {
		t.Fatalf("the reset dropped a live floor: %d", got)
	}
}

func TestPreparedRequestHoldsNoFloorTableAndCommitKeepsLiveFloors(t *testing.T) {
	f, p := floorFixture(t)
	req := must(f.m.PreparePublish(f.ctx, p))
	if strings.Contains(string(req.DocJSON), "acct-") || len(req.Doc.MinVersions) != 0 || req.Annex != nil {
		t.Fatalf("the request holds a table or an annex: %s", req.DocJSON)
	}
	// A floor raised while the request waits stays: floors only go up.
	// (SetMinVersion moves the version, so the request is stale; prepare
	// again after it, then raise nothing and commit.)
	if err := f.m.SetMinVersion(p, "acct-1", 4); err != nil {
		t.Fatal(err)
	}
	if err := f.m.CommitPublish(p, signOffline(t, f, req), f.root.Public(), f.rootAlg); !errors.Is(err, keys.ErrRequestMismatch) {
		t.Fatalf("a stale request: %v", err)
	}
	req = must(f.m.PreparePublish(f.ctx, p))
	if err := f.m.CommitPublish(p, signOffline(t, f, req), f.root.Public(), f.rootAlg); err != nil {
		t.Fatal(err)
	}
	d := f.m.Doc(p)
	if d.MinVersion("acct-1") != 4 || d.MinVersion("acct-2") != 5 {
		t.Fatalf("the commit lost the live floors: %v", d.MinVersions)
	}
	// A restart replays the floors from the log.
	if got := second(t, f).Doc(p); got.MinVersion("acct-1") != 4 || got.MinVersion("acct-2") != 5 {
		t.Fatalf("the replayed manager lost the floors: %v", got.MinVersions)
	}
}

func TestRetiringRequestCarriesTheLiveFloorsAsAnAnnex(t *testing.T) {
	f, p := floorFixture(t)
	req := must(f.m.PreparePublishRetiringFloors(f.ctx, p))
	if req.Annex == nil || req.Annex.Floors["acct-1"] != 3 || req.Annex.Floors["acct-2"] != 5 {
		t.Fatalf("annex: %+v", req.Annex)
	}
	if req.Annex.SHA256 != req.Annex.Digest() || len(req.Annex.SHA256) != 64 {
		t.Fatalf("annex digest: %q", req.Annex.SHA256)
	}
	if strings.Contains(string(req.DocJSON), "acct-") {
		t.Fatalf("the signed bytes name an account: %s", req.DocJSON)
	}
	// The same table gives the same digest.
	if keys.NewFloorAnnex(map[string]uint64{"acct-2": 5, "acct-1": 3}).SHA256 != req.Annex.SHA256 {
		t.Fatal("digest depends on map order")
	}
	// The annex survives adoption on another replica and is checked there.
	m2 := second(t, f)
	if err := m2.AdoptPending(req); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	bad := req
	bad.Annex = &keys.FloorAnnex{Floors: map[string]uint64{"acct-1": 3}, SHA256: req.Annex.SHA256}
	if err := m2.AdoptPending(bad); !errors.Is(err, keys.ErrRequestMismatch) {
		t.Fatalf("an annex that does not match its digest: %v", err)
	}
	high := req
	high.Annex = keys.NewFloorAnnex(map[string]uint64{"acct-1": 99})
	if err := m2.AdoptPending(high); !errors.Is(err, keys.ErrRequestMismatch) {
		t.Fatalf("an annex above the live floors: %v", err)
	}
}

func TestViewFollowsASetWithoutAFloorTableAndKeepsItsLocalFloor(t *testing.T) {
	f, p := floorFixture(t)
	pin := f.m.Doc(p).FloorsOnlyFor("acct-1") // floor 3
	state := filepath.Join(t.TempDir(), "keys.jws")
	roots := must(roottrust.Pinned(f.root.Public(), f.rootAlg))
	v := must(keys.NewViewRoots(p, roots, pin, state))

	signed := must(f.m.Publish(f.ctx, p, f.root))
	if err := v.Update(signed); err != nil {
		t.Fatalf("a keys-only set after a pin that holds a floor: %v", err)
	}
	if got := v.MinVersion("acct-1"); got != 3 {
		t.Fatalf("the set lowered the local floor: %d", got)
	}
	if got := v.MinVersion("acct-2"); got != 0 {
		t.Fatalf("the view learned another account: %d", got)
	}
	// Restart: same pin, stored set.
	v2 := must(keys.NewViewRoots(p, roots, pin, state))
	want, _ := payloadOf(t, signed)
	if e, ver := v2.Version(); e != want.Epoch || ver != want.Version {
		t.Fatalf("the restarted view lost its stored set: %d %d, want %d %d", e, ver, want.Epoch, want.Version)
	}
	if got := v2.MinVersion("acct-1"); got != 3 {
		t.Fatalf("after a restart the floor is %d", got)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatal(err)
	}
}

// A set that still carries a table (signed before the retirement) lowers
// nothing and raises what it names; a later set with none lowers nothing.
func TestViewTakesTheHigherFloorOfAnOldSetAndNeverLowersIt(t *testing.T) {
	f, p := floorFixture(t)
	old := f.m.Doc(p)
	// Build an old-form set by hand: the root signs a doc with a table.
	older := old
	older.Version++
	older.MinVersions = map[string]uint64{"acct-1": 2, "acct-2": 5}
	oldSigned := must(jws.Sign(f.root, keys.DocType, mustJSON(older)))

	pin := old.FloorsOnlyFor("acct-1") // pin floor 3
	v := f.view(t, p, pin)
	if err := v.Update(oldSigned); err != nil {
		t.Fatalf("an old set whose floor for acct-1 is below the pin: %v", err)
	}
	if v.MinVersion("acct-1") != 3 || v.MinVersion("acct-2") != 5 {
		t.Fatalf("floors after the old set: %d %d", v.MinVersion("acct-1"), v.MinVersion("acct-2"))
	}
	newer := older
	newer.Version++
	newer.MinVersions = nil
	if err := v.Update(must(jws.Sign(f.root, keys.DocType, mustJSON(newer)))); err != nil {
		t.Fatal(err)
	}
	if v.MinVersion("acct-1") != 3 || v.MinVersion("acct-2") != 5 {
		t.Fatalf("a set without a table lowered a floor: %d %d", v.MinVersion("acct-1"), v.MinVersion("acct-2"))
	}
}

// The view still refuses what it refused for keys: a removed key stays
// removed and a known key id keeps its public key.
func TestViewStillKeepsTheKeyRules(t *testing.T) {
	f, p := floorFixture(t)
	v := f.view(t, p, f.m.Doc(p).FloorsOnlyFor("acct-1"))
	cur := f.m.Doc(p)
	bad := cur
	bad.Version++
	bad.Keys = append([]keys.PublishedKey(nil), cur.Keys...)
	bad.Keys[0].PublicDER = append([]byte{0}, bad.Keys[0].PublicDER...)
	if err := v.Update(must(jws.Sign(f.root, keys.DocType, mustJSON(bad)))); !errors.Is(err, keys.ErrKeyChanged) {
		t.Fatalf("a changed public key: %v", err)
	}
}
