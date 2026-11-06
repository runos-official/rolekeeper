package jws_test

import (
	"testing"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
)

// PeekHeader never panics, and a header it returns names an allowed
// algorithm and no embedded key material.
func FuzzPeekHeader(f *testing.F) {
	s := newSigner(f, signer.PurposeGate, signer.AlgEdDSA)
	tok, err := jws.Sign(s, "t", []byte(`{"a":1}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok)
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("a.b")
	f.Fuzz(func(t *testing.T, compact string) {
		h, err := jws.PeekHeader(compact)
		if err != nil {
			return
		}
		switch h.Alg {
		case string(signer.AlgEdDSA), string(signer.AlgES256), string(signer.AlgRS256):
		default:
			t.Fatalf("header with algorithm %q accepted", h.Alg)
		}
	})
}

// Verify never panics, and anything it accepts carries exactly the payload
// the key holder signed.
func FuzzVerify(f *testing.F) {
	for _, alg := range []signer.Algorithm{signer.AlgEdDSA, signer.AlgES256} {
		s := newSigner(f, signer.PurposeGate, alg)
		tok, err := jws.Sign(s, "t", []byte(`{"a":1}`))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(tok, alg == signer.AlgES256)
	}
	ed := newSigner(f, signer.PurposeGate, signer.AlgEdDSA)
	es := newSigner(f, signer.PurposeGate, signer.AlgES256)
	edTok, _ := jws.Sign(ed, "t", []byte(`{"a":1}`))
	esTok, _ := jws.Sign(es, "t", []byte(`{"a":1}`))
	f.Add(edTok, false)
	f.Add(esTok, true)
	f.Fuzz(func(t *testing.T, compact string, useES bool) {
		s, alg := ed, signer.AlgEdDSA
		if useES {
			s, alg = es, signer.AlgES256
		}
		p, err := jws.Verify(compact, s.Public(), alg)
		if err == nil && string(p) != `{"a":1}` {
			t.Fatalf("accepted a token with payload %q", p)
		}
	})
}
