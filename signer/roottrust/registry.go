package roottrust

// The registry of root-signed artifacts. Every document the
// offline root signs is listed here, and is checked by VerifyArtifact (a
// JWS) or VerifyRawArtifact (a raw signature): the chain rule of this
// package, nothing else. The re-sign list of a handover, the ceremony and
// root-check read the same list. A test in the deploy module scans the
// repository for root signature checks that bypass it.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
)

// Artifact names.
const (
	ArtKeySet          = "key set"
	ArtAnchorBundle    = "anchor bundle"
	ArtLegacyAllowlist = "legacy allowlist"
	ArtBMCEnrolment    = "BMC enrolment certificate"
	ArtHandover        = "root handover"
	ArtCutoff          = "overlap cutoff"
	// ArtIntakeKey is the signer's intake key:
	// a client verifies it before it encrypts a secret.
	ArtIntakeKey = "intake key statement"
)

// JWS types of root-signed artifacts (keys.DocType and anchors.BundleType
// are these).
const (
	TypKeySet       = "runos.keyset+jwt"
	TypAnchorBundle = "runos.anchors+jwt"
	TypIntakeKey    = "runos.intake+jwt"
)

// Artifact is one kind of document the offline root signs.
type Artifact struct {
	Name string
	// Typ is the JWS typ header; empty for a raw signature (Raw).
	Typ string
	Raw bool
	// ReSign: the new root re-signs the current one at a handover, before
	// the overlap ends; else what to do instead.
	ReSign bool
	Note   string
	// Purposes are the signer purposes the artifact exists for (key sets,
	// anchor bundles): one re-sign item each.
	Purposes []signer.Purpose
	// Verb is how the re-sign list names an item ("re-sign", "re-sign
	// anchors", "certify again").
	Verb string
}

// Artifacts is every root-signed artifact.
var Artifacts = []Artifact{
	{Name: ArtKeySet, Typ: TypKeySet, ReSign: true, Note: "the current set of every key set roid serves", Purposes: KeySetPurposes, Verb: "re-sign"},
	{Name: ArtAnchorBundle, Typ: TypAnchorBundle, ReSign: true, Note: "the bundle of each trust anchor that holds a root-signed reset", Purposes: AnchorPurposes, Verb: "re-sign anchors"},
	{Name: ArtLegacyAllowlist, Raw: true, Note: "signed once at the cutover: finish the legacy period before the overlap ends"},
	{Name: ArtBMCEnrolment, Raw: true, ReSign: true, Note: "each broker's enrolment key, with the new root (roid root-check -bmc-cert)", Verb: "certify again"},
	{Name: ArtIntakeKey, Typ: TypIntakeKey, ReSign: true, Note: "the signer's intake key for company client secrets (POST /v1/platform/intake-key/request)",
		Purposes: []signer.Purpose{PurposeIntake}, Verb: "re-sign"},
	{Name: ArtHandover, Typ: HandoverType, Note: "the chain itself"},
	{Name: ArtCutoff, Typ: CutoffType, Note: "the chain itself"},
}

// PurposeIntake names the intake key statement in root-check and in the
// re-sign list. It is no signer key purpose: the key comes
// from the data key ring.
const PurposeIntake signer.Purpose = "upstream-intake"

// AnchorPurposes are the anchor bundles the offline root signs a reset of
// (anchors.RootSignedPurposes).
var AnchorPurposes = []signer.Purpose{signer.PurposeAgentCA, signer.PurposeSvcMTLS}

// ReSignItems is the re-sign list of a handover, from the registry:
// one line per purpose of a re-signed artifact, else one per artifact.
func ReSignItems() []string {
	var out []string
	for _, a := range Artifacts {
		if !a.ReSign {
			continue
		}
		if len(a.Purposes) == 0 {
			out = append(out, a.Verb+" "+a.Name+": "+a.Note)
			continue
		}
		for _, p := range a.Purposes {
			out = append(out, a.Verb+" "+string(p)+" ("+a.Name+": "+a.Note+")")
		}
	}
	return out
}

// KeySetPurposes are the key sets the offline root signs (keys.RootSignedPurposes).
var KeySetPurposes = []signer.Purpose{signer.PurposeEmergencyRoster, signer.PurposeGate, signer.PurposePolicyBundle,
	signer.PurposeVPNLease, signer.PurposeOperationGrant, signer.PurposeDecisionReceipt, signer.PurposeJobGrant,
	signer.PurposeAuditCheckpoint}

func artifact(name string) (Artifact, error) {
	for _, a := range Artifacts {
		if a.Name == name {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: %q is not a root-signed artifact", ErrBadStatement, name)
}

// VerifyArtifact is the one check of a root-signed JWS artifact: the
// registry's type, the keyset-root purpose, and v's chain rule.
func VerifyArtifact(v Verifier, name, compact string) ([]byte, error) {
	a, err := artifact(name)
	if err != nil {
		return nil, err
	}
	if a.Raw {
		return nil, fmt.Errorf("%w: %s is a raw signature", ErrBadStatement, name)
	}
	h, err := jws.PeekHeader(compact)
	if err != nil {
		return nil, err
	}
	if h.Typ != a.Typ || h.Purpose != string(signer.PurposeKeySetRoot) {
		return nil, fmt.Errorf("%w: a %s has type %s and the root's purpose", jws.ErrBadSignature, name, a.Typ)
	}
	if v == nil {
		return nil, fmt.Errorf("%w: no root is pinned", jws.ErrBadSignature)
	}
	return v.Verify(compact)
}

// RawVerifier is a Verifier that checks raw root signatures (a Trust).
type RawVerifier interface {
	VerifyRaw(msg, sig []byte, signedAt time.Time) error
}

// VerifyRawArtifact is the one check of a raw root signature: the
// registry, and v's chain rule with the artifact's own signing time
// (zero: none, so only the current root counts).
func VerifyRawArtifact(v Verifier, name string, msg, sig []byte, signedAt time.Time) error {
	a, err := artifact(name)
	if err != nil {
		return err
	}
	if !a.Raw {
		return fmt.Errorf("%w: %s is a JWS", ErrBadStatement, name)
	}
	r, ok := v.(RawVerifier)
	if !ok {
		return fmt.Errorf("%w: no root chain to check a %s with", jws.ErrBadSignature, name)
	}
	return r.VerifyRaw(msg, sig, signedAt)
}

func rawVerify(pub crypto.PublicKey, msg, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, d[:], sig)
	}
	return false
}
