package token_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/revlog"
	"github.com/runos-official/rolekeeper/internal/signer/token"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type env struct {
	ctx   context.Context
	now   time.Time
	b     *signer.SoftBackend
	m     *keys.Manager
	root  *signer.Signer
	views map[signer.Purpose]*keys.View
	iss   *token.Issuer
}

func setup(t testing.TB, alg signer.Algorithm) *env {
	t.Helper()
	e := &env{ctx: context.Background(), now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC), views: map[signer.Purpose]*keys.View{}}
	clk := func() time.Time { return e.now }
	e.b = signer.NewSoftBackend()
	l := must(revlog.Open(filepath.Join(t.TempDir(), "rev.log")))
	t.Cleanup(func() { l.Close() })
	e.m = keys.NewManager(e.b, l, clk)
	off := signer.NewOfflineRootBackend()
	rk := must(off.CreateKey(e.ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA))
	e.root = must(signer.New(e.ctx, off, rk.ID, signer.PurposeKeySetRoot))
	for _, p := range []signer.Purpose{signer.PurposeKubernetesIssuer, signer.PurposeVPNLease, signer.PurposeGate, signer.PurposeOperationGrant, signer.PurposePolicyBundle} {
		d := must(e.m.Bootstrap(e.ctx, p, alg))
		e.views[p] = must(keys.NewView(p, e.root.Public(), signer.AlgEdDSA, d))
	}
	e.iss = &token.Issuer{Keys: e.m, Name: "https://id.runos.invalid", Now: clk}
	return e
}

func (e *env) verifier(p signer.Purpose, aud string, classes ...string) *token.Verifier {
	return &token.Verifier{
		Purpose: p, Issuer: "https://id.runos.invalid", Audience: aud, Classes: classes,
		Keys: e.views[p], Now: func() time.Time { return e.now },
	}
}

func k8sClaims() token.Claims {
	return token.Claims{Claims: jwt.Claims{Subject: "runos:u:person-1", Audience: jwt.Audience{"cluster-a"}}, Class: "person.cli", Account: "acct-1"}
}

func TestIssueAndVerifyBothAlgorithms(t *testing.T) {
	for _, alg := range []signer.Algorithm{signer.AlgEdDSA, signer.AlgES256} {
		e := setup(t, alg)
		tok := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 15*time.Minute))
		c, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli").Verify(tok)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if c.Subject != "runos:u:person-1" || c.Purpose != signer.PurposeKubernetesIssuer || c.ID == "" {
			t.Fatalf("claims %+v", c)
		}
	}
}

// A VPN lease is refused as a Kubernetes token and
// a Kubernetes token is refused by the VPN server, with wrong_key_purpose.
func TestAT_PLT_006_CrossPurposeTokensRefused(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	lease := must(e.iss.Issue(e.ctx, signer.PurposeVPNLease, token.Claims{Claims: jwt.Claims{Subject: "person-1", Audience: jwt.Audience{"cluster-a"}}, Class: "vpn.lease"}, time.Hour))
	kt := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 15*time.Minute))
	k8sV := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli", "vpn.lease")
	vpnV := e.verifier(signer.PurposeVPNLease, "cluster-a", "person.cli", "vpn.lease")
	_, err := k8sV.Verify(lease)
	if !errors.Is(err, token.ErrWrongKeyPurpose) || token.Code(err) != "wrong_key_purpose" {
		t.Fatalf("lease at k8s: %v", err)
	}
	if token.HTTPStatus(err) != 401 {
		t.Fatal("must map to HTTP 401 auth.invalid_credential")
	}
	if _, err := vpnV.Verify(kt); !errors.Is(err, token.ErrWrongKeyPurpose) {
		t.Fatalf("k8s token at vpn: %v", err)
	}
	// An operation grant is not a gate cookie either.
	og := must(e.iss.Issue(e.ctx, signer.PurposeOperationGrant, token.Claims{Claims: jwt.Claims{Subject: "op", Audience: jwt.Audience{"nodeward"}}, Class: "operation.grant"}, time.Minute))
	if _, err := e.verifier(signer.PurposeGate, "nodeward", "operation.grant").Verify(og); !errors.Is(err, token.ErrWrongKeyPurpose) {
		t.Fatalf("grant at gate: %v", err)
	}
}

// A token whose header says vpn-lease but whose claims say another purpose.
func TestPurposeClaimMustMatchHeaderAndVerifier(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	s := must(e.m.ActiveSigner(e.ctx, signer.PurposeVPNLease))
	exp := jwt.NewNumericDate(e.now.Add(time.Hour))
	raw, _ := json.Marshal(map[string]any{"iss": "https://id.runos.invalid", "aud": "cluster-a", "exp": exp, "purpose": "kubernetes-issuer", "cls": "vpn.lease"})
	tok := must(jws.Sign(s, signer.PurposeVPNLease.TokenType(), raw))
	if _, err := e.verifier(signer.PurposeVPNLease, "cluster-a", "vpn.lease").Verify(tok); !errors.Is(err, token.ErrWrongKeyPurpose) {
		t.Fatalf("want wrong_key_purpose, got %v", err)
	}
}

func TestIssuerRefusesNonTokenPurposesAndLongLifetimes(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	if _, err := e.iss.Issue(e.ctx, signer.PurposeAgentCA, k8sClaims(), time.Hour); !errors.Is(err, token.ErrWrongKeyPurpose) {
		t.Fatalf("agent-ca is not a token purpose: %v", err)
	}
	// A 12-hour VPN lease is refused; 8 hours is the cap.
	if _, err := e.iss.Issue(e.ctx, signer.PurposeVPNLease, k8sClaims(), 12*time.Hour); !errors.Is(err, token.ErrLifetimeTooLong) {
		t.Fatalf("12h lease: %v", err)
	}
	if _, err := e.iss.Issue(e.ctx, signer.PurposeVPNLease, k8sClaims(), 8*time.Hour); err != nil {
		t.Fatalf("8h lease: %v", err)
	}
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func validPayload(e *env) []byte {
	raw, _ := json.Marshal(map[string]any{
		"iss": "https://id.runos.invalid", "sub": "runos:u:person-1", "aud": "cluster-a",
		"exp": jwt.NewNumericDate(e.now.Add(10 * time.Minute)), "purpose": "kubernetes-issuer", "cls": "person.cli",
	})
	return raw
}

func TestAlgNoneRefused(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	kid := e.m.Doc(signer.PurposeKubernetesIssuer).Active().Kid
	hdr, _ := json.Marshal(map[string]string{"alg": "none", "kid": kid, "typ": signer.PurposeKubernetesIssuer.TokenType(), "purpose": "kubernetes-issuer"})
	for _, tok := range []string{enc(hdr) + "." + enc(validPayload(e)) + ".", enc(hdr) + "." + enc(validPayload(e))} {
		_, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli").Verify(tok)
		if err == nil || (!errors.Is(err, token.ErrAlgorithmNotAllowed) && !errors.Is(err, token.ErrMalformed)) {
			t.Fatalf("alg none: %v", err)
		}
	}
}

// Classic confusion: HS256 with the public key bytes as the HMAC secret.
func TestAlgorithmConfusionHS256WithPublicKeyRefused(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	k := e.m.Doc(signer.PurposeKubernetesIssuer).Active()
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": k.Kid, "typ": signer.PurposeKubernetesIssuer.TokenType(), "purpose": "kubernetes-issuer"})
	in := enc(hdr) + "." + enc(validPayload(e))
	mac := hmac.New(sha256.New, k.PublicDER)
	mac.Write([]byte(in))
	tok := in + "." + enc(mac.Sum(nil))
	if _, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli").Verify(tok); !errors.Is(err, token.ErrAlgorithmNotAllowed) {
		t.Fatalf("HS256 confusion: %v", err)
	}
}

// ES256 header against an EdDSA key id (cross-algorithm on the allowlist).
func TestAlgorithmConfusionAcrossAllowlistRefused(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	realKid := e.m.Doc(signer.PurposeKubernetesIssuer).Active().Kid
	atk := signer.NewSoftBackend()
	ak := must(atk.CreateKey(e.ctx, signer.PurposeKubernetesIssuer, signer.AlgES256))
	as := must(signer.New(e.ctx, atk, ak.ID, signer.PurposeKubernetesIssuer))
	tok := must(jws.Sign(as, signer.PurposeKubernetesIssuer.TokenType(), validPayload(e)))
	// Swap the attacker kid for the real EdDSA kid; re-sign the new header.
	parts := strings.Split(tok, ".")
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": realKid, "typ": signer.PurposeKubernetesIssuer.TokenType(), "purpose": "kubernetes-issuer"})
	forged := must(signRaw(as, enc(hdr)+"."+parts[1]))
	if _, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli").Verify(forged); !errors.Is(err, token.ErrAlgorithmNotAllowed) {
		t.Fatalf("ES256 on an EdDSA kid: %v", err)
	}
}

func signRaw(s *signer.Signer, signingInput string) (string, error) {
	d := sha256.Sum256([]byte(signingInput))
	der, err := s.Sign(nil, d[:], cryptoSHA256)
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc(der), nil // DER, not raw r||s: it must fail anyway
}

func TestEmbeddedJWKRefused(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	atk := signer.NewSoftBackend()
	ak := must(atk.CreateKey(e.ctx, signer.PurposeKubernetesIssuer, signer.AlgEdDSA))
	as := must(signer.New(e.ctx, atk, ak.ID, signer.PurposeKubernetesIssuer))
	js := must(jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: opaque{as}, KeyID: ""}},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(signer.PurposeKubernetesIssuer.TokenType())).WithHeader("purpose", "kubernetes-issuer")))
	obj := must(js.Sign(validPayload(e)))
	tok := must(obj.CompactSerialize())
	if _, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli").Verify(tok); !errors.Is(err, token.ErrForbiddenHeader) {
		t.Fatalf("embedded jwk: %v", err)
	}
}

func TestWrongAudienceIssuerClassAndType(t *testing.T) {
	e := setup(t, signer.AlgES256)
	tok := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 15*time.Minute))
	if _, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-b", "person.cli").Verify(tok); !errors.Is(err, token.ErrWrongAudience) {
		t.Fatalf("wrong audience: %v", err)
	}
	v := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli")
	v.Issuer = "https://evil.invalid"
	if _, err := v.Verify(tok); !errors.Is(err, token.ErrWrongIssuer) {
		t.Fatalf("wrong issuer: %v", err)
	}
	if _, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.session.high").Verify(tok); !errors.Is(err, token.ErrWrongClass) {
		t.Fatalf("wrong class: %v", err)
	}
	if _, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a").Verify(tok); !errors.Is(err, token.ErrWrongClass) {
		t.Fatal("a verifier with no allowed classes must refuse everything")
	}
	s := must(e.m.ActiveSigner(e.ctx, signer.PurposeKubernetesIssuer))
	odd := must(jws.Sign(s, keys.DocType, validPayload(e)))
	if _, err := v.Verify(odd); !errors.Is(err, token.ErrWrongType) {
		t.Fatalf("key-set typ presented as token: %v", err)
	}
}

func TestExpiredNotYetValidAndMissingExp(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	v := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli")
	tok := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 15*time.Minute))
	e.now = e.now.Add(15*time.Minute + token.DefaultLeeway + time.Second)
	if _, err := v.Verify(tok); !errors.Is(err, token.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	c := k8sClaims()
	c.NotBefore = jwt.NewNumericDate(e.now.Add(10 * time.Minute))
	nyv := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, c, 15*time.Minute))
	if _, err := v.Verify(nyv); !errors.Is(err, token.ErrNotYetValid) {
		t.Fatalf("not yet valid: %v", err)
	}
	s := must(e.m.ActiveSigner(e.ctx, signer.PurposeKubernetesIssuer))
	raw, _ := json.Marshal(map[string]any{"iss": "https://id.runos.invalid", "aud": "cluster-a", "purpose": "kubernetes-issuer", "cls": "person.cli"})
	noExp := must(jws.Sign(s, signer.PurposeKubernetesIssuer.TokenType(), raw))
	if _, err := v.Verify(noExp); !errors.Is(err, token.ErrMissingClaim) {
		t.Fatalf("no exp: %v", err)
	}
	// A verifier also caps exp at the purpose lifetime, even for a validly signed token.
	raw, _ = json.Marshal(map[string]any{"iss": "https://id.runos.invalid", "aud": "cluster-a", "purpose": "kubernetes-issuer", "cls": "person.cli",
		"iat": jwt.NewNumericDate(e.now), "exp": jwt.NewNumericDate(e.now.Add(30 * 24 * time.Hour))})
	long := must(jws.Sign(s, signer.PurposeKubernetesIssuer.TokenType(), raw))
	if _, err := v.Verify(long); !errors.Is(err, token.ErrLifetimeTooLong) {
		t.Fatalf("30-day token: %v", err)
	}
}

func TestRemovedKeyAndUnknownKidRefused(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	p := signer.PurposeGate
	v := e.verifier(p, "gate-a", "person.session")
	c := token.Claims{Claims: jwt.Claims{Subject: "person-1", Audience: jwt.Audience{"gate-a"}}, Class: "person.session"}
	tok := must(e.iss.Issue(e.ctx, p, c, 15*time.Minute))
	if _, err := v.Verify(tok); err != nil {
		t.Fatal(err)
	}
	bad := e.m.Doc(p).Active().Kid
	if err := e.views[p].Update(must(e.m.Compromise(e.ctx, p, bad, e.root))); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); !errors.Is(err, token.ErrKeyRemoved) {
		t.Fatalf("removed key: %v", err)
	}
	fresh := must(e.iss.Issue(e.ctx, p, c, 15*time.Minute))
	if _, err := v.Verify(fresh); err != nil {
		t.Fatalf("replacement key token: %v", err)
	}
	atk := signer.NewSoftBackend()
	ak := must(atk.CreateKey(e.ctx, p, signer.AlgEdDSA))
	forged := must(jws.Sign(must(signer.New(e.ctx, atk, ak.ID, p)), p.TokenType(), validPayload(e)))
	if _, err := v.Verify(forged); !errors.Is(err, token.ErrUnknownKey) {
		t.Fatalf("unknown kid: %v", err)
	}
}

func TestTamperedPayloadRefused(t *testing.T) {
	e := setup(t, signer.AlgES256)
	tok := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 15*time.Minute))
	parts := strings.Split(tok, ".")
	var m map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(b, &m)
	m["sub"] = "runos:u:admin"
	nb, _ := json.Marshal(m)
	parts[1] = enc(nb)
	if _, err := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli").Verify(strings.Join(parts, ".")); !errors.Is(err, token.ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestRevokedCredentialRefused(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	c := k8sClaims()
	c.Parent = "session-9"
	tok := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, c, 15*time.Minute))
	v := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli")
	v.Revoked = func(c *token.Claims) error {
		if c.Parent == "session-9" {
			return errors.New("parent revoked")
		}
		return nil
	}
	if _, err := v.Verify(tok); !errors.Is(err, token.ErrRevoked) {
		t.Fatalf("revoked parent: %v", err)
	}
}

// Signer down means no token, and existing tokens still verify.
func TestAT_SIG_005_SignerDownNoTokenExistingVerifies(t *testing.T) {
	e := setup(t, signer.AlgEdDSA)
	v := e.verifier(signer.PurposeKubernetesIssuer, "cluster-a", "person.cli")
	tok := must(e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 15*time.Minute))
	e.b.SetDown(true)
	out, err := e.iss.Issue(e.ctx, signer.PurposeKubernetesIssuer, k8sClaims(), 15*time.Minute)
	if !errors.Is(err, signer.ErrUnavailable) || out != "" || token.HTTPStatus(err) != 503 {
		t.Fatalf("signer down: %q %v", out, err)
	}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("existing token must verify while signer is down: %v", err)
	}
}
