package signer_test

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
)

// recorder wraps a backend and keeps every sign request it sees.
type recorder struct {
	*signer.SoftBackend
	mu   sync.Mutex
	reqs []signer.SignRequest
}

func (r *recorder) Sign(ctx context.Context, req signer.SignRequest) ([]byte, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return r.SoftBackend.Sign(ctx, req)
}

// retirer is a backend that retires a key against evidence, as the signer
// socket client does.
type retirer struct {
	*signer.SoftBackend
	keyID, evidence, decision string
	disableCalled             bool
}

func (r *retirer) RetireKey(ctx context.Context, keyID, evidence string) error {
	r.keyID, r.evidence, r.decision = keyID, evidence, signer.DecisionFromContext(ctx)
	return nil
}

func (r *retirer) DisableKey(ctx context.Context, keyID string) error {
	r.disableCalled = true
	return r.SoftBackend.DisableKey(ctx, keyID)
}

func newKey(t *testing.T, b signer.Backend, p signer.Purpose, alg signer.Algorithm) signer.KeyInfo {
	t.Helper()
	info, err := b.CreateKey(context.Background(), p, alg)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestRetireWithAPlainBackendDisablesTheKey(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	info := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA)
	if err := signer.Retire(ctx, b, info.ID, "ignored evidence"); err != nil {
		t.Fatal(err)
	}
	got, _ := b.PublicKey(ctx, info.ID)
	if !got.Disabled || got.DisabledAt.IsZero() {
		t.Fatalf("key after retire: %+v", got)
	}
}

func TestRetireWithARetirerPassesTheEvidenceAndNamesTheDecision(t *testing.T) {
	r := &retirer{SoftBackend: signer.NewSoftBackend()}
	if err := signer.Retire(context.Background(), r, "key-1", "the.root.signed.set"); err != nil {
		t.Fatal(err)
	}
	if r.keyID != "key-1" || r.evidence != "the.root.signed.set" || r.decision != "retire-key-1" {
		t.Fatalf("retirer saw %q %q %q", r.keyID, r.evidence, r.decision)
	}
	if r.disableCalled {
		t.Fatal("a Retirer must be retired against evidence, not disabled outright")
	}
}

func TestRetireKeepsADecisionThatTheCallerAlreadyNamed(t *testing.T) {
	r := &retirer{SoftBackend: signer.NewSoftBackend()}
	ctx := signer.ContextWithDecision(context.Background(), "decision-7")
	if err := signer.Retire(ctx, r, "key-1", "e"); err != nil {
		t.Fatal(err)
	}
	if r.decision != "decision-7" {
		t.Fatalf("decision %q", r.decision)
	}
}

func TestDecisionTravelsInTheContext(t *testing.T) {
	ctx := context.Background()
	if signer.DecisionFromContext(ctx) != "" {
		t.Fatal("a bare context carries a decision")
	}
	ctx = signer.ContextWithDecision(ctx, "d-1")
	if got := signer.DecisionFromContext(ctx); got != "d-1" {
		t.Fatalf("got %q", got)
	}
}

func TestWithDecisionSendsTheIdOnEverySignAndLeavesTheOriginalAlone(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{SoftBackend: signer.NewSoftBackend()}
	info := newKey(t, rec, signer.PurposeGate, signer.AlgEdDSA)
	s, err := signer.New(ctx, rec, info.ID, signer.PurposeGate)
	if err != nil {
		t.Fatal(err)
	}
	withID := s.WithDecision("decision-1")
	if _, err := withID.Sign(rand.Reader, []byte("m"), crypto.Hash(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(rand.Reader, []byte("m"), nil); err != nil {
		t.Fatal(err)
	}
	if len(rec.reqs) != 2 || rec.reqs[0].DecisionID != "decision-1" || rec.reqs[1].DecisionID != "" {
		t.Fatalf("requests %+v", rec.reqs)
	}
	if rec.reqs[0].KeyID != info.ID || rec.reqs[0].Purpose != signer.PurposeGate {
		t.Fatalf("the request does not carry the key and purpose: %+v", rec.reqs[0])
	}
}

func TestNewSignerReportsWhatItHolds(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	info := newKey(t, b, signer.PurposeVPNLease, signer.AlgES256)
	s, err := signer.New(ctx, b, info.ID, signer.PurposeVPNLease)
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID() != info.ID || s.Purpose() != signer.PurposeVPNLease || s.Algorithm() != signer.AlgES256 {
		t.Fatalf("signer %q %q %q", s.KeyID(), s.Purpose(), s.Algorithm())
	}
	if got := s.Info(); got.ID != info.ID || string(got.PublicDER) != string(info.PublicDER) {
		t.Fatalf("info %+v", got)
	}
	if _, ok := s.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("public key %T", s.Public())
	}
}

func TestNewSignerRefusesAnUnknownKeyAndAKeyOfAnotherPurpose(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	if _, err := signer.New(ctx, b, "nope", signer.PurposeGate); !errors.Is(err, signer.ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	info := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA)
	if _, err := signer.New(ctx, b, info.ID, signer.PurposeVPNLease); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Fatalf("wrong purpose: %v", err)
	}
}

// badKeyBackend serves a key record whose public key does not fit.
type badKeyBackend struct {
	*signer.SoftBackend
	info signer.KeyInfo
}

func (b badKeyBackend) PublicKey(context.Context, string) (signer.KeyInfo, error) { return b.info, nil }

func TestNewSignerRefusesARecordWhoseKeyDoesNotFitItsAlgorithm(t *testing.T) {
	b := signer.NewSoftBackend()
	info := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA)
	info.Algorithm = signer.AlgES256 // the key is Ed25519
	_, err := signer.New(context.Background(), badKeyBackend{b, info}, info.ID, signer.PurposeGate)
	if !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Fatalf("err %v", err)
	}
}

func TestKeyInfoPublicKeyRefusesWhatItCannotUse(t *testing.T) {
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgEdDSA, PublicDER: []byte("not der")}).PublicKey(); err == nil {
		t.Error("garbage DER accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgES256, PublicDER: der}).PublicKey(); !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Errorf("a P-384 key as ES256: %v", err)
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKIXPublicKey(edPub)
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgES256, PublicDER: edDER}).PublicKey(); !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Errorf("an Ed25519 key as ES256: %v", err)
	}
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xDER, _ := x509.MarshalPKIXPublicKey(x.PublicKey())
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgEdDSA, PublicDER: xDER}).PublicKey(); !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Errorf("a key agreement key: %v", err)
	}
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgEdDSA, PublicDER: edDER}).PublicKey(); err != nil {
		t.Errorf("a good Ed25519 key refused: %v", err)
	}
}

func TestCheckDigestHoldsEachAlgorithmToItsShape(t *testing.T) {
	d32 := make([]byte, 32)
	cases := []struct {
		name   string
		alg    signer.Algorithm
		digest []byte
		hash   crypto.Hash
		want   error
	}{
		{"EdDSA message", signer.AlgEdDSA, []byte("m"), 0, nil},
		{"EdDSA prehash", signer.AlgEdDSA, d32, crypto.SHA256, signer.ErrBadDigest},
		{"EdDSA empty", signer.AlgEdDSA, nil, 0, signer.ErrBadDigest},
		{"ES256 digest", signer.AlgES256, d32, crypto.SHA256, nil},
		{"ES256 short", signer.AlgES256, d32[:31], crypto.SHA256, signer.ErrBadDigest},
		{"ES256 no hash", signer.AlgES256, d32, 0, signer.ErrBadDigest},
		{"RS256 digest", signer.AlgRS256, d32, crypto.SHA256, nil},
		{"RS256 other hash", signer.AlgRS256, d32, crypto.SHA512, signer.ErrBadDigest},
		{"unknown algorithm", signer.Algorithm("HS256"), d32, crypto.SHA256, signer.ErrUnsupportedAlgorithm},
	}
	for _, c := range cases {
		err := signer.CheckDigest(c.alg, c.digest, c.hash)
		if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.want)
		}
	}
}

func TestSignerSignChecksTheDigestBeforeItCallsCustody(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{SoftBackend: signer.NewSoftBackend()}
	info := newKey(t, rec, signer.PurposeGate, signer.AlgES256)
	s, err := signer.New(ctx, rec, info.ID, signer.PurposeGate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(rand.Reader, []byte("short"), crypto.SHA256); !errors.Is(err, signer.ErrBadDigest) {
		t.Fatalf("err %v", err)
	}
	if len(rec.reqs) != 0 {
		t.Fatalf("custody was asked to sign a bad digest: %+v", rec.reqs)
	}
	d := sha256.Sum256([]byte("m"))
	if _, err := s.Sign(rand.Reader, d[:], crypto.SHA256); err != nil {
		t.Fatal(err)
	}
}

func TestSignerSignReturnsTheCustodyError(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	info := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA)
	s, _ := signer.New(ctx, b, info.ID, signer.PurposeGate)
	b.SetDown(true)
	if _, err := s.Sign(rand.Reader, []byte("m"), crypto.Hash(0)); !errors.Is(err, signer.ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
}

func TestSoftBackendCountsOnlySignaturesThatWereMade(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	info := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA)
	s, _ := signer.New(ctx, b, info.ID, signer.PurposeGate)
	for range 3 {
		if _, err := s.Sign(rand.Reader, []byte("m"), crypto.Hash(0)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Sign(ctx, signer.SignRequest{KeyID: info.ID, Purpose: signer.PurposeVPNLease, Digest: []byte("m")}); err == nil {
		t.Fatal("a wrong purpose signed")
	}
	if b.SignCount() != 3 {
		t.Fatalf("count %d, want 3", b.SignCount())
	}
}

func TestSoftBackendOutageFailsEveryCallClosedAndRecovers(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	info := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA)
	b.SetDown(true)
	if _, err := b.CreateKey(ctx, signer.PurposeGate, signer.AlgEdDSA); !errors.Is(err, signer.ErrUnavailable) {
		t.Errorf("CreateKey: %v", err)
	}
	if _, err := b.PublicKey(ctx, info.ID); !errors.Is(err, signer.ErrUnavailable) {
		t.Errorf("PublicKey: %v", err)
	}
	if _, err := b.Sign(ctx, signer.SignRequest{KeyID: info.ID, Purpose: signer.PurposeGate, Digest: []byte("m")}); !errors.Is(err, signer.ErrUnavailable) {
		t.Errorf("Sign: %v", err)
	}
	if err := b.DisableKey(ctx, info.ID); !errors.Is(err, signer.ErrUnavailable) {
		t.Errorf("DisableKey: %v", err)
	}
	b.SetDown(false)
	if _, err := b.PublicKey(ctx, info.ID); err != nil {
		t.Errorf("after the outage: %v", err)
	}
}

func TestSoftBackendUnknownKeyIsRefusedEverywhere(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	if _, err := b.PublicKey(ctx, "x"); !errors.Is(err, signer.ErrUnknownKey) {
		t.Errorf("PublicKey: %v", err)
	}
	if _, err := b.Sign(ctx, signer.SignRequest{KeyID: "x"}); !errors.Is(err, signer.ErrUnknownKey) {
		t.Errorf("Sign: %v", err)
	}
	if err := b.DisableKey(ctx, "x"); !errors.Is(err, signer.ErrUnknownKey) {
		t.Errorf("DisableKey: %v", err)
	}
}

func TestDisablingAKeyTwiceKeepsTheFirstTimeAndTheKeyStaysReadable(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	info := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA)
	if err := b.DisableKey(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	first, _ := b.PublicKey(ctx, info.ID)
	time.Sleep(2 * time.Millisecond)
	if err := b.DisableKey(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	second, _ := b.PublicKey(ctx, info.ID)
	if !first.Disabled || !second.DisabledAt.Equal(first.DisabledAt) {
		t.Fatalf("first %+v second %+v", first, second)
	}
	if _, err := second.PublicKey(); err != nil {
		t.Fatalf("a disabled key must stay readable for verifiers: %v", err)
	}
}

func TestCustodyLabelIsProvenanceOnTheKeyRecord(t *testing.T) {
	b := signer.NewSoftBackend()
	if got := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA).Custody; got != "soft" {
		t.Fatalf("default custody %q", got)
	}
	b.SetCustody("signerd/soft")
	if got := newKey(t, b, signer.PurposeGate, signer.AlgEdDSA).Custody; got != "signerd/soft" {
		t.Fatalf("custody %q", got)
	}
	root := signer.NewOfflineRootBackend()
	if got := newKey(t, root, signer.PurposeKeySetRoot, signer.AlgEdDSA).Custody; got != "offline-root-sim" {
		t.Fatalf("root custody %q", got)
	}
}

func TestBackendsHoldOnlyTheirOwnPurposes(t *testing.T) {
	ctx := context.Background()
	online, root := signer.NewSoftBackend(), signer.NewOfflineRootBackend()
	if _, err := online.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Errorf("online backend made a root key: %v", err)
	}
	for _, p := range signer.AllPurposes() {
		if _, err := root.CreateKey(ctx, p, signer.AlgEdDSA); !errors.Is(err, signer.ErrWrongPurpose) {
			t.Errorf("root backend made a %s key: %v", p, err)
		}
	}
	if _, err := online.CreateKey(ctx, signer.Purpose("made-up"), signer.AlgEdDSA); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Errorf("unknown purpose: %v", err)
	}
	if _, err := online.CreateKey(ctx, signer.PurposeGate, signer.Algorithm("HS256")); !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Errorf("unknown algorithm: %v", err)
	}
}

func TestPurposeCapsAreTheDocumentedOnes(t *testing.T) {
	want := map[signer.Purpose]time.Duration{
		signer.PurposeKubernetesIssuer: 15 * time.Minute,
		signer.PurposeVPNLease:         8 * time.Hour,
		signer.PurposeGate:             15 * time.Minute,
		signer.PurposeOperationGrant:   5 * time.Minute,
		signer.PurposePolicyBundle:     24 * time.Hour,
		signer.PurposeAgentCA:          24 * time.Hour,
		signer.PurposeSvcMTLS:          72 * time.Hour,
		signer.PurposeDecisionReceipt:  signer.MaxReceiptLifetime,
		signer.PurposeJobGrant:         signer.MaxJobGrantLifetime,
		signer.PurposeAuditCheckpoint:  12 * time.Hour,
		signer.PurposeEmergencyRoster:  24 * time.Hour,
	}
	for _, p := range signer.AllPurposes() {
		w, ok := want[p]
		if !ok {
			t.Errorf("purpose %s has no expected cap in this test", p)
			continue
		}
		if got := p.MaxTokenLifetime(); got != w {
			t.Errorf("%s: cap %s, want %s", p, got, w)
		}
		if got := p.RotationOverlap(); got != 2*w {
			t.Errorf("%s: overlap %s, want %s", p, got, 2*w)
		}
	}
	if signer.PurposeKeySetRoot.MaxTokenLifetime() != 0 || signer.Purpose("made-up").MaxTokenLifetime() != 0 {
		t.Error("the root and an unknown purpose sign no credential")
	}
	if signer.Purpose("made-up").Valid() || signer.Purpose("").Valid() {
		t.Error("an unknown purpose is valid")
	}
	if signer.PurposeKeySetRoot.Rotates() {
		t.Error("the offline root rotates")
	}
}

func TestEveryPurposeHasItsOwnTokenType(t *testing.T) {
	seen := map[string]signer.Purpose{}
	for _, p := range append(signer.AllPurposes(), signer.PurposeKeySetRoot) {
		typ := p.TokenType()
		if other, dup := seen[typ]; dup {
			t.Errorf("%s and %s share the type %s", p, other, typ)
		}
		seen[typ] = p
	}
	if got := signer.PurposeGate.TokenType(); got != "runos.gate+jwt" {
		t.Errorf("gate type %q", got)
	}
}

func TestOnlyEdDSAAndES256AreOnTheAllowlist(t *testing.T) {
	if !signer.AlgEdDSA.Allowed() || !signer.AlgES256.Allowed() || signer.AlgRS256.Allowed() || signer.Algorithm("none").Allowed() {
		t.Fatal("the allowlist is wrong")
	}
}
