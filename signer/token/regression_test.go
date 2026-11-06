package token_test

// Kubernetes and gate tokens
// live at most 15 minutes, or 5 minutes for privileged groups.

import (
	"errors"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/token"
)

func TestKubernetesAndGateTokensCappedAt15Minutes(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	for _, p := range []signer.Purpose{signer.PurposeKubernetesIssuer, signer.PurposeGate} {
		if got := p.MaxTokenLifetime(); got != 15*time.Minute {
			t.Errorf("%s: MaxTokenLifetime %s, want 15m", p, got)
		}
		c := k8sClaims()
		if _, err := e.iss.Issue(e.ctx, p, c, 16*time.Minute); !errors.Is(err, token.ErrLifetimeTooLong) {
			t.Errorf("%s: 16m token: want ErrLifetimeTooLong, got %v", p, err)
		}
		if _, err := e.iss.Issue(e.ctx, p, c, 15*time.Minute); err != nil {
			t.Errorf("%s: 15m token refused: %v", p, err)
		}
		c.Privileged = true
		if _, err := e.iss.Issue(e.ctx, p, c, 6*time.Minute); !errors.Is(err, token.ErrLifetimeTooLong) {
			t.Errorf("%s: 6m privileged token: want ErrLifetimeTooLong, got %v", p, err)
		}
		tok, err := e.iss.Issue(e.ctx, p, c, 5*time.Minute)
		if err != nil {
			t.Fatalf("%s: 5m privileged token refused: %v", p, err)
		}
		if _, err := e.verifier(p, "cluster-a", "person.cli").Verify(tok); err != nil {
			t.Errorf("%s: 5m privileged token does not verify: %v", p, err)
		}
	}
}
