package token_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/signer"
)

// Verify never panics, and any token it accepts has the claims the issuer
// signed.
func FuzzVerify(f *testing.F) {
	e := setup(f, signer.AlgEdDSA)
	tok, err := e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 5*time.Minute)
	if err != nil {
		f.Fatal(err)
	}
	v := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli")
	want, err := v.Verify(tok)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok)
	f.Add(tok + ".")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := v.Verify(s)
		if err == nil && !reflect.DeepEqual(got, want) {
			t.Fatalf("accepted a token with other claims: %+v", got)
		}
	})
}
