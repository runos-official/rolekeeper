package keys_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
)

func compromisedOnOne(t *testing.T, f *fixture, p signer.Purpose) (keys.Request, string) {
	t.Helper()
	must(f.m.Bootstrap(f.ctx, p, signer.AlgEdDSA))
	if err := f.m.SetMinVersion(p, "acct-x", 5); err != nil {
		t.Fatal(err)
	}
	active := f.m.Doc(p).Active().Kid
	return must(f.m.PrepareCompromise(f.ctx, p, active)), active
}

// A compromise reset that one replica prepared can be committed by another
// replica after adoption: an operator's install
// call may land on any replica.
func TestAdoptPendingLetsAnotherReplicaCommitACompromise(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	req, bad := compromisedOnOne(t, f, p)
	signed := signOffline(t, f, req)
	m2 := second(t, f)
	if err := m2.AdoptPending(req); err != nil {
		t.Fatalf("adopt the compromise: %v", err)
	}
	if err := m2.CommitCompromise(p, signed, f.root.Public(), f.rootAlg); err != nil {
		t.Fatalf("commit after adopt: %v", err)
	}
	d := m2.Doc(p)
	if d.Find(bad) != nil || d.Epoch != req.Doc.Epoch {
		t.Fatalf("after the reset the set holds %s or has epoch %d (want %d)", bad, d.Epoch, req.Doc.Epoch)
	}
}

// Adopting a compromise never brings in a key custody does not hold, keeps
// the removed key, skips an epoch or lowers a floor.
func TestAdoptPendingRefusesAChangedCompromise(t *testing.T) {
	f := setup(t)
	p := signer.PurposeGate
	req, bad := compromisedOnOne(t, f, p)
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
	foreign := must(signer.NewSoftBackend().CreateKey(f.ctx, p, signer.AlgEdDSA))
	cases := map[string]keys.Request{
		"key outside custody": tamper(func(d *keys.Doc) {
			d.Keys = append(d.Keys, keys.PublishedKey{Kid: foreign.ID, Alg: foreign.Algorithm, State: keys.StateNext, PublicDER: foreign.PublicDER})
		}),
		"removed key kept": tamper(func(d *keys.Doc) {
			old := f.m.Doc(p).Find(bad)
			d.Keys = append(d.Keys, *old)
		}),
		"epoch skip":    tamper(func(d *keys.Doc) { d.Epoch += 2 }),
		"lowered floor": tamper(func(d *keys.Doc) { d.MinVersions = map[string]uint64{"acct-x": 0} }),
		"other kid":     func() keys.Request { r := req; r.Kid = "not-a-key"; return r }(),
		"publish kind":  func() keys.Request { r := req; r.Kind = keys.RequestPublish; return r }(),
	}
	for name, r := range cases {
		if err := m2.AdoptPending(r); err == nil {
			t.Errorf("%s: adopted", name)
		} else if !errors.Is(err, keys.ErrRequestMismatch) && name != "publish kind" {
			t.Errorf("%s: %v, want ErrRequestMismatch", name, err)
		}
	}
}
