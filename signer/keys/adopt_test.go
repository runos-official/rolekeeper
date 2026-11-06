package keys_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
)

// second is another replica's manager on the same log and custody.
func second(t *testing.T, f *fixture) *keys.Manager {
	t.Helper()
	m := keys.RestoreManager(f.b, f.log, f.clk.now, keys.Snapshot{})
	if err := m.Replay(f.log.Since(0)); err != nil {
		t.Fatal(err)
	}
	return m
}

func preparedOnOne(t *testing.T, f *fixture, p signer.Purpose) keys.Request {
	t.Helper()
	must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	f.clk.advance(p.RotationOverlap())
	if err := f.m.Rotate(f.ctx, p, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	return must(f.m.PreparePublish(f.ctx, p))
}

// A replica that did not prepare the request commits the root's signature
// after adopting the stored request.
func TestAdoptPendingLetsAnotherReplicaCommit(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	req := preparedOnOne(t, f, p)
	signed := signOffline(t, f, req)
	m2 := second(t, f)
	if err := m2.CommitPublish(p, signed, f.root.Public(), f.rootAlg); !errors.Is(err, keys.ErrNoRequest) {
		t.Fatalf("a replica without the request committed: %v", err)
	}
	if err := m2.AdoptPending(req); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if err := m2.CommitPublish(p, signed, f.root.Public(), f.rootAlg); err != nil {
		t.Fatalf("commit after adopt: %v", err)
	}
	if got := m2.Doc(p).Version; got != req.Doc.Version {
		t.Fatalf("version %d, want %d", got, req.Doc.Version)
	}
}

// Adoption never brings in a key or floor the current set does not hold:
// a stored request that a database writer changed is refused before any
// signature is checked.
func TestAdoptPendingRefusesAChangedRequest(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	req := preparedOnOne(t, f, p)
	m2 := second(t, f)
	tamper := func(change func(d *keys.Doc)) keys.Request {
		var d keys.Doc
		if err := json.Unmarshal(req.DocJSON, &d); err != nil {
			t.Fatal(err)
		}
		change(&d)
		r := req
		r.DocJSON = mustJSON(d)
		r.Doc = d
		return r
	}
	other := must(signer.NewSoftBackend().CreateKey(f.ctx, p, signer.AlgEdDSA))
	cases := map[string]keys.Request{
		"swapped public key": tamper(func(d *keys.Doc) { d.Keys[0].PublicDER = other.PublicDER }),
		"extra key": tamper(func(d *keys.Doc) {
			d.Keys = append(d.Keys, keys.PublishedKey{Kid: other.ID, Alg: other.Algorithm, State: keys.StateNext, PublicDER: other.PublicDER})
		}),
		"version jump":    tamper(func(d *keys.Doc) { d.Version += 5 }),
		"lowered floor":   tamper(func(d *keys.Doc) { d.MinVersions = map[string]uint64{"acct-x": 0} }),
		"compromise kind": func() keys.Request { r := req; r.Kind = keys.RequestCompromise; return r }(),
		"other purpose":   func() keys.Request { r := req; r.Purpose = signer.PurposePolicyBundle; return r }(),
	}
	for name, r := range cases {
		if err := m2.AdoptPending(r); err == nil {
			t.Errorf("%s: adopted", name)
		}
	}
}
