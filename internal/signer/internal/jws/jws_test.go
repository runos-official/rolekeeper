package jws_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
)

func newSigner(t testing.TB, p signer.Purpose, alg signer.Algorithm) *signer.Signer {
	t.Helper()
	ctx := context.Background()
	b := signer.NewSoftBackend()
	k, err := b.CreateKey(ctx, p, alg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signer.New(ctx, b, k.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignBindsPurposeTypeAndKid(t *testing.T) {
	for _, alg := range []signer.Algorithm{signer.AlgEdDSA, signer.AlgES256} {
		s := newSigner(t, signer.PurposeGate, alg)
		c, err := jws.Sign(s, "runos.test+jwt", []byte(`{"a":1}`))
		if err != nil {
			t.Fatal(err)
		}
		h, err := jws.PeekHeader(c)
		if err != nil {
			t.Fatal(err)
		}
		if h.Alg != string(alg) || h.Kid != s.KeyID() || h.Typ != "runos.test+jwt" || h.Purpose != string(signer.PurposeGate) {
			t.Fatalf("header %+v", h)
		}
		p, err := jws.Verify(c, s.Public(), alg)
		if err != nil || string(p) != `{"a":1}` {
			t.Fatalf("verify: %q %v", p, err)
		}
	}
}

func TestPeekRefusesNoneHS256AndEmbeddedKeys(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	cases := map[string]struct {
		hdr  string
		want error
	}{
		"none":  {`{"alg":"none"}`, jws.ErrAlgorithmNotAllowed},
		"HS256": {`{"alg":"HS256","kid":"k"}`, jws.ErrAlgorithmNotAllowed},
		"RS256": {`{"alg":"RS256","kid":"k"}`, jws.ErrAlgorithmNotAllowed},
		"jwk":   {`{"alg":"EdDSA","jwk":{"kty":"OKP"}}`, jws.ErrForbiddenHeader},
		"jku":   {`{"alg":"EdDSA","jku":"https://x.invalid"}`, jws.ErrForbiddenHeader},
		"crit":  {`{"alg":"EdDSA","crit":["exp"]}`, jws.ErrForbiddenHeader},
	}
	for name, c := range cases {
		tok := enc(c.hdr) + "." + enc(`{}`) + "."
		if _, err := jws.PeekHeader(tok); !errors.Is(err, c.want) {
			t.Fatalf("%s: want %v, got %v", name, c.want, err)
		}
	}
	if _, err := jws.PeekHeader("a.b"); !errors.Is(err, jws.ErrMalformed) {
		t.Fatalf("two parts: %v", err)
	}
}

func TestVerifyRefusesWrongKeyAndTamper(t *testing.T) {
	s := newSigner(t, signer.PurposeGate, signer.AlgEdDSA)
	other := newSigner(t, signer.PurposeGate, signer.AlgEdDSA)
	c, _ := jws.Sign(s, "t", []byte(`{"a":1}`))
	if _, err := jws.Verify(c, other.Public(), signer.AlgEdDSA); !errors.Is(err, jws.ErrBadSignature) {
		t.Fatalf("other key: %v", err)
	}
	parts := strings.Split(c, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))
	if _, err := jws.Verify(strings.Join(parts, "."), s.Public(), signer.AlgEdDSA); !errors.Is(err, jws.ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := jws.Verify(c, s.Public(), signer.AlgES256); !errors.Is(err, jws.ErrAlgorithmNotAllowed) {
		t.Fatalf("alg mismatch with registered key alg: %v", err)
	}
}
