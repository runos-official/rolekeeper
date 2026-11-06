package conformance_test

// The generator of testdata/conformance/vectors.json. It builds a signing
// side out of the TEST-ONLY keys in testkeys_test.go and a fixed clock, signs
// every artifact with the real packages of this repository, and records the
// outcome that a verifier must reach. The outcomes are written down here by
// hand: the generator does not copy what the verifier happened to say, it
// stops when the verifier says something else.
//
// Regenerate (only when a release adds a vector version, never to make a
// failing test pass):
//
//	go test ./conformance -run TestFileIsWhatTheGeneratorWrites -update

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/conformance"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/revlog"
	"github.com/runos-official/rolekeeper/signer/token"
)

const (
	issuerName = "https://roid.example.com"
	account    = "acct-a"
	cluster    = "cl-1"
	nonce      = "Y29uZm9ybWFuY2Utbm9uY2UtMDAwMQ" // 22 characters of base64url
	notice     = "TEST-ONLY vectors. Every key behind them is derived from a public label and must never be trusted outside tests. The file holds public keys and signed tokens only. Do not edit by hand: see docs/conformance.md."
)

var clock = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// world is one signing side: key manager, issuer and the trust it implies.
type world struct {
	t      *testing.T
	km     *keys.Manager
	issuer *token.Issuer
	trust  bundle.Trust
	root   *signer.Signer
}

// newWorld bootstraps a signer with the bundle key specs and a root.
func newWorld(t *testing.T, bundleKeys []keySpec, rootLabel string) *world {
	t.Helper()
	ctx := context.Background()
	log, err := revlog.Open(filepath.Join(t.TempDir(), "rev.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	rootBackend := newFixedBackend(clock, spec(rootLabel))
	rootInfo, err := rootBackend.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	root, err := signer.New(ctx, rootBackend, rootInfo.ID, signer.PurposeKeySetRoot)
	if err != nil {
		t.Fatal(err)
	}

	now := func() time.Time { return clock }
	km := keys.NewManager(newFixedBackend(clock, bundleKeys...), log, now)
	doc, err := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	return &world{
		t: t, km: km, root: root,
		issuer: &token.Issuer{Keys: km, Name: issuerName, Now: now},
		trust:  bundle.Trust{Issuer: issuerName, Cluster: cluster, RootPublicDER: rootInfo.PublicDER, RootAlg: signer.AlgEdDSA, BundleKeys: doc},
	}
}

// must stops the generator on an error. generate recovers it into a test failure.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// body is a bundle of the shape roid serves: the deny list and one binding.
func (w *world) body(version uint64, mutate func(*bundle.Bundle)) bundle.Bundle {
	w.t.Helper()
	deny := must(compile.DenyObjects("pv-3", account, nil, clock))
	b := bundle.Bundle{
		Account: account, Cluster: cluster, Version: version, PolicyVersion: "pv-3", Namespaces: []string{"apps"}, IssuedAt: clock,
		Objects: append(deny, kobj.Object{
			Kind: kobj.KindRoleBinding, Name: "runos:view:g:ops", Namespace: "apps", Labels: compile.Labels("pv-3", account),
			Subjects: []kobj.Subject{{Kind: "Group", Name: compile.GroupSubject("ops", compile.RoleView), APIGroup: "rbac.authorization.k8s.io"}},
			RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: kobj.KindClusterRole, Name: compile.RoleView},
		}),
	}
	if mutate != nil {
		mutate(&b)
	}
	return b
}

func (w *world) seal(b bundle.Bundle) bundle.Envelope {
	w.t.Helper()
	raw := must(bundle.Seal(context.Background(), w.issuer, b, 15*time.Minute))
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		w.t.Fatal(err)
	}
	return env
}

// mint signs a policy-bundle token with a chosen id: the relay tokens need an
// id that is the same on every run.
func (w *world) mint(class, subject, acct, clusterName, id string, ttl time.Duration) string {
	w.t.Helper()
	return must(w.issuer.Issue(context.Background(), signer.PurposePolicyBundle, token.Claims{
		Claims: jwt.Claims{Subject: subject, ID: id, Audience: jwt.Audience{bundle.Audience(clusterName)}}, Class: class, Account: acct,
	}, ttl))
}

func flipChar(s string, i int) string {
	b := []byte(s)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// segments splits a compact token into header, payload and signature.
func segments(t *testing.T, tok string) [3]string {
	t.Helper()
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		t.Fatalf("token has %d segments", len(p))
	}
	return [3]string{p[0], p[1], p[2]}
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// digestOf is the content digest a verifier computes for an envelope: the
// digest of the body as it decodes.
func digestOf(env bundle.Envelope) string {
	var b bundle.Bundle
	if err := json.Unmarshal(env.Body, &b); err != nil {
		panic(err)
	}
	return bundle.ContentDigest(b)
}

// generate builds the whole file.
func generate(t *testing.T) []byte {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("generator: %v", r)
		}
	}()
	ctx := context.Background()
	w := newWorld(t, []keySpec{spec(labelBundleKey), spec(labelBundleNext)}, labelRoot)
	activeKid := w.trust.BundleKeys.Active().Kid

	var cases []conformance.Case
	add := func(c conformance.Case) { cases = append(cases, c) }
	later := func(d time.Duration) *time.Time { x := clock.Add(d); return &x }

	// ---- bundles that must be accepted
	env7 := w.seal(w.body(7, nil))
	digest7 := digestOf(env7)
	add(conformance.Case{ID: "bundle-ok", Kind: conformance.KindBundle, Description: "a full bundle at version 7: the deny objects and one group binding",
		Envelope: &env7, Expect: conformance.Expect{OK: true, Version: 7, ContentDigest: digest7}})
	envDeny := w.seal(w.body(8, func(b *bundle.Bundle) { b.DenyOnly = true; b.Objects = b.Objects[:3] }))
	add(conformance.Case{ID: "bundle-deny-only-ok", Kind: conformance.KindBundle, Description: "a deny-only bundle: the projection was refused and only the deny list is sent",
		Envelope: &envDeny, Expect: conformance.Expect{OK: true, Version: 8, ContentDigest: digestOf(envDeny)}})
	retire := func(b *bundle.Bundle) { b.Retire = true; b.Objects = b.Objects[:3] }
	envRetire := w.seal(w.body(9, retire))
	add(conformance.Case{ID: "bundle-retire-ok", Kind: conformance.KindBundle, Description: "a retire bundle: the cluster leaves the account",
		Envelope: &envRetire, Expect: conformance.Expect{OK: true, Version: 9, ContentDigest: digestOf(envRetire)}})

	// ---- bundles that must be refused
	badBody := env7
	badBody.Body = append([]byte(nil), env7.Body...)
	badBody.Body[strings.Index(string(badBody.Body), `"version":7`)+len(`"version":`)] = '8'
	add(conformance.Case{ID: "bundle-body-changed", Kind: conformance.KindBundle, Description: "one digit of the body changed after signing (version 7 became 8): the token id no longer matches",
		Envelope: &badBody, Expect: conformance.Expect{Error: "digest_mismatch"}})

	seg := segments(t, env7.Bundle)
	badSig := env7
	badSig.Bundle = strings.Join([]string{seg[0], seg[1], flipChar(seg[2], 10)}, ".")
	add(conformance.Case{ID: "bundle-signature-changed", Kind: conformance.KindBundle, Description: "one character of the signature changed",
		Envelope: &badSig, Expect: conformance.Expect{Error: "bad_signature"}})
	badPayload := env7
	badPayload.Bundle = strings.Join([]string{seg[0], flipChar(seg[1], 20), seg[2]}, ".")
	add(conformance.Case{ID: "bundle-claims-changed", Kind: conformance.KindBundle, Description: "one character of the claims changed: the signature no longer covers them",
		Envelope: &badPayload, Expect: conformance.Expect{Error: "bad_signature"}})

	add(conformance.Case{ID: "bundle-expired", Kind: conformance.KindBundle, Description: "the token lives 15 minutes; the verifier clock is 16 minutes later (the leeway is 30 seconds)",
		Now: later(16 * time.Minute), Envelope: &env7, Expect: conformance.Expect{Error: "expired"}})
	add(conformance.Case{ID: "bundle-not-yet-valid", Kind: conformance.KindBundle, Description: "the verifier clock is 5 minutes before the token was issued",
		Now: later(-5 * time.Minute), Envelope: &env7, Expect: conformance.Expect{Error: "not_yet_valid"}})
	add(conformance.Case{ID: "bundle-other-cluster-verifier", Kind: conformance.KindBundle, Description: "the verifier belongs to another cluster than the token audience",
		Cluster: "cl-2", Envelope: &env7, Expect: conformance.Expect{Error: "wrong_audience"}})
	add(conformance.Case{ID: "bundle-other-account-verifier", Kind: conformance.KindBundle, Description: "the verifier expects another account than the bundle holds",
		Account: "acct-b", Envelope: &env7, Expect: conformance.Expect{Error: "wrong_account"}})

	otherBody := w.body(10, func(b *bundle.Bundle) { b.Cluster = "cl-2"; b.Format = bundle.Format })
	otherRaw := must(json.Marshal(otherBody))
	otherSum := sha256.Sum256(otherRaw)
	envOther := bundle.Envelope{Bundle: w.mint(bundle.Class, bundle.Subject, account, cluster, hex.EncodeToString(otherSum[:]), 15*time.Minute), Body: otherRaw}
	add(conformance.Case{ID: "bundle-body-names-other-cluster", Kind: conformance.KindBundle, Description: "a correctly signed token for this cluster over a body that names another cluster",
		Envelope: &envOther, Expect: conformance.Expect{Error: "wrong_cluster"}})

	freshOther := w.mint("k8s-rbac-fresh", "k8s-rbac-fresh", account, cluster, bundle.FreshID(nonce, digest7), 15*time.Minute)
	envFresh := bundle.Envelope{Bundle: freshOther, Body: env7.Body}
	add(conformance.Case{ID: "bundle-is-a-fresh-token", Kind: conformance.KindBundle, Description: "the token is a valid fresh token, not a bundle token",
		Envelope: &envFresh, Expect: conformance.Expect{Error: "not_an_rbac_bundle"}})

	add(conformance.Case{ID: "bundle-without-body", Kind: conformance.KindBundle, Description: "an envelope with a token and no body",
		Envelope: &bundle.Envelope{Bundle: env7.Bundle}, Expect: conformance.Expect{Error: "bad_format"}})
	add(conformance.Case{ID: "bundle-empty-envelope", Kind: conformance.KindBundle, Description: "an empty envelope",
		Envelope: &bundle.Envelope{}, Expect: conformance.Expect{Error: "bad_format"}})

	// A signer that nobody published, and one that signs under a published id.
	stranger := newWorld(t, []keySpec{spec(labelStrangerKey), spec(labelStrangerNxt)}, labelOtherRoot)
	envStranger := stranger.seal(stranger.body(7, nil))
	add(conformance.Case{ID: "bundle-signed-by-an-unpublished-key", Kind: conformance.KindBundle, Description: "signed by a key that the pinned key set does not hold",
		Envelope: &envStranger, Expect: conformance.Expect{Error: "unknown_key"}})
	forged := newWorld(t, []keySpec{{id: activeKid, label: labelForgedKey}, {id: w.trust.BundleKeys.Keys[1].Kid, label: labelForgedKey + "-two"}}, labelOtherRoot)
	envForged := forged.seal(forged.body(7, nil))
	add(conformance.Case{ID: "bundle-forged-under-a-published-key-id", Kind: conformance.KindBundle, Description: "signed by another key that uses the id of the published active key",
		Envelope: &envForged, Expect: conformance.Expect{Error: "bad_signature"}})

	// Header attacks. The payload is the real one, the header is not.
	hdr := func(alg string) map[string]any {
		return map[string]any{"alg": alg, "typ": signer.PurposePolicyBundle.TokenType(), "kid": activeKid, "purpose": string(signer.PurposePolicyBundle)}
	}
	none := env7
	none.Bundle = b64(hdr("none")) + "." + seg[1] + "."
	add(conformance.Case{ID: "bundle-alg-none", Kind: conformance.KindBundle, Description: "alg none with an empty signature",
		Envelope: &none, Expect: conformance.Expect{Error: "algorithm_not_allowed"}})
	mac := hmac.New(sha256.New, w.trust.BundleKeys.Active().PublicDER)
	hsInput := b64(hdr("HS256")) + "." + seg[1]
	mac.Write([]byte(hsInput))
	hs := env7
	hs.Bundle = hsInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	add(conformance.Case{ID: "bundle-alg-hs256-with-the-public-key", Kind: conformance.KindBundle, Description: "HS256 keyed with the public key bytes as the secret",
		Envelope: &hs, Expect: conformance.Expect{Error: "algorithm_not_allowed"}})

	// ---- fresh tokens
	fresh := w.mint("k8s-rbac-fresh", "k8s-rbac-fresh", account, cluster, bundle.FreshID(nonce, digest7), 15*time.Minute)
	sealed := must(bundle.SealFresh(ctx, w.issuer, account, cluster, nonce, digest7))
	if sealed != fresh {
		t.Fatal("bundle.SealFresh and the minted fresh token differ: the vector would not describe what roid signs")
	}
	add(conformance.Case{ID: "fresh-ok", Kind: conformance.KindFresh, Description: "the fresh token for the nonce and the content digest of bundle 7",
		Token: fresh, Nonce: nonce, ContentDigest: digest7, Expect: conformance.Expect{OK: true}})
	add(conformance.Case{ID: "fresh-other-nonce", Kind: conformance.KindFresh, Description: "the applier chose another nonce",
		Token: fresh, Nonce: "b3RoZXItbm9uY2UtMDAwMDAwMQ", ContentDigest: digest7, Expect: conformance.Expect{Error: "fresh_token_mismatch"}})
	env8 := w.seal(w.body(8, nil))
	add(conformance.Case{ID: "fresh-other-content", Kind: conformance.KindFresh, Description: "the envelope that was served is not the one the token names",
		Token: fresh, Nonce: nonce, ContentDigest: digestOf(env8), Expect: conformance.Expect{Error: "fresh_token_mismatch"}})
	fseg := segments(t, fresh)
	add(conformance.Case{ID: "fresh-signature-changed", Kind: conformance.KindFresh, Description: "one character of the signature changed",
		Token: strings.Join([]string{fseg[0], fseg[1], flipChar(fseg[2], 10)}, "."), Nonce: nonce, ContentDigest: digest7, Expect: conformance.Expect{Error: "bad_signature"}})
	add(conformance.Case{ID: "fresh-expired", Kind: conformance.KindFresh, Description: "the verifier clock is 16 minutes after the token was issued",
		Now: later(16 * time.Minute), Token: fresh, Nonce: nonce, ContentDigest: digest7, Expect: conformance.Expect{Error: "expired"}})
	add(conformance.Case{ID: "fresh-other-account-verifier", Kind: conformance.KindFresh, Description: "the verifier expects another account",
		Account: "acct-b", Token: fresh, Nonce: nonce, ContentDigest: digest7, Expect: conformance.Expect{Error: "wrong_account"}})
	add(conformance.Case{ID: "fresh-is-a-bundle-token", Kind: conformance.KindFresh, Description: "a bundle token offered as a fresh token",
		Token: env7.Bundle, Nonce: nonce, ContentDigest: digest7, Expect: conformance.Expect{Error: "fresh_token_mismatch"}})

	// ---- refusals
	refusalCluster := w.mint("k8s-rbac-refusal", "k8s-rbac-refusal:cluster", account, cluster, "refusal-conformance-0001", 15*time.Minute)
	refusalRetired := w.mint("k8s-rbac-refusal", "k8s-rbac-refusal:retired", account, cluster, "refusal-conformance-0002", 15*time.Minute)
	add(conformance.Case{ID: "refusal-cluster-ok", Kind: conformance.KindRefusal, Description: "roid refuses the cluster",
		Token: refusalCluster, Expect: conformance.Expect{OK: true, Reason: "cluster"}})
	add(conformance.Case{ID: "refusal-retired-ok", Kind: conformance.KindRefusal, Description: "roid refuses a cluster that was retired",
		Token: refusalRetired, Expect: conformance.Expect{OK: true, Reason: "retired"}})
	rseg := segments(t, refusalCluster)
	add(conformance.Case{ID: "refusal-signature-changed", Kind: conformance.KindRefusal, Description: "one character of the signature changed",
		Token: strings.Join([]string{rseg[0], rseg[1], flipChar(rseg[2], 10)}, "."), Expect: conformance.Expect{Error: "bad_signature"}})
	add(conformance.Case{ID: "refusal-expired", Kind: conformance.KindRefusal, Description: "the verifier clock is 16 minutes after the token was issued; an expired refusal does not count",
		Now: later(16 * time.Minute), Token: refusalCluster, Expect: conformance.Expect{Error: "expired"}})
	add(conformance.Case{ID: "refusal-other-cluster-verifier", Kind: conformance.KindRefusal, Description: "the refusal names cl-1; the verifier is cl-2",
		Cluster: "cl-2", Token: refusalCluster, Expect: conformance.Expect{Error: "wrong_audience"}})
	add(conformance.Case{ID: "refusal-is-a-bundle-token", Kind: conformance.KindRefusal, Description: "a bundle token offered as a refusal",
		Token: env7.Bundle, Expect: conformance.Expect{Error: "bad_refusal"}})
	odd := w.mint("k8s-rbac-refusal", "k8s-rbac-refusal:whatever", account, cluster, "refusal-conformance-0003", 15*time.Minute)
	add(conformance.Case{ID: "refusal-unknown-reason", Kind: conformance.KindRefusal, Description: "a signed refusal with a reason other than cluster or retired",
		Token: odd, Expect: conformance.Expect{Error: "bad_refusal"}})

	// ---- key sets
	signed := must(w.km.Publish(ctx, signer.PurposePolicyBundle, w.root))
	add(conformance.Case{ID: "keyset-root-signed-ok", Kind: conformance.KindKeySet, Description: "the key set at version 2, signed by the pinned root",
		Signed: signed, Expect: conformance.Expect{OK: true}})
	rootless := newWorld(t, []keySpec{spec(labelBundleKey), spec(labelBundleNext)}, labelOtherRoot)
	signedByOther := must(rootless.km.Publish(ctx, signer.PurposePolicyBundle, rootless.root))
	add(conformance.Case{ID: "keyset-signed-by-an-unpinned-root", Kind: conformance.KindKeySet, Description: "the same keys, signed by a root that the trust does not pin",
		Signed: signedByOther, Expect: conformance.Expect{Error: "bad_signature"}})
	kseg := segments(t, signed)
	add(conformance.Case{ID: "keyset-changed", Kind: conformance.KindKeySet, Description: "one character of the signed key set changed",
		Signed: strings.Join([]string{kseg[0], flipChar(kseg[1], 30), kseg[2]}, "."), Expect: conformance.Expect{Error: "bad_signature"}})
	add(conformance.Case{ID: "keyset-not-a-token", Kind: conformance.KindKeySet, Description: "text that is not a signed key set",
		Signed: "not-a-key-set", Expect: conformance.Expect{Error: "malformed"}})

	f := conformance.File{Format: 1, Notice: notice, Clock: clock, Account: account, Trust: w.trust, Cases: cases}
	// The expectations above are written by hand. Stop when a verifier of
	// today does not reach them, so the file never records a guess.
	for _, c := range f.Cases {
		if err := f.Check(c, t.TempDir()); err != nil {
			t.Fatalf("generator: %v", err)
		}
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}
