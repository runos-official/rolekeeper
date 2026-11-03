// Package signer is the RunOS signer: one key per purpose,
// held behind a custody Backend so that the identity service only ever
// holds a crypto.Signer handle, never private key material.
package signer

import "time"

// Purpose names what a key may sign. A key is created for exactly one
// purpose and the purpose is checked at the custody layer (Backend.Sign),
// bound into every signed object, and checked again by every verifier.
type Purpose string

const (
	PurposeKubernetesIssuer Purpose = "kubernetes-issuer"
	PurposeVPNLease         Purpose = "vpn-lease"
	PurposeGate             Purpose = "gate"
	PurposeOperationGrant   Purpose = "operation-grant"
	PurposePolicyBundle     Purpose = "policy-bundle"
	PurposeAgentCA          Purpose = "agent-ca"
	// PurposeEmergencyRoster signs the emergency-key list that VPN servers
	// and Kubernetes API servers pin. The offline
	// root certifies the roster key in the root-signed key set, so a key
	// enrolment or removal is an online signed action, and only a change of
	// the roster key itself needs the root.
	PurposeEmergencyRoster Purpose = "emergency-roster"
	// PurposeSvcMTLS is the CA key for internal service-to-service mTLS
	// certificates. It is its own key, separate from the
	// agent CA and every token key. It signs certificates, never tokens.
	PurposeSvcMTLS Purpose = "svc-mtls"
	// PurposeDecisionReceipt signs decision receipts: a short-lived signed
	// copy of one permit, for one action, one account, one resource and
	// one service. A verifier checks it offline against the root-signed
	// key set of this purpose. A denial never gets one.
	PurposeDecisionReceipt Purpose = "decision-receipt"
	// PurposeJobGrant signs job grants: a signed statement that one
	// service may act for one account for one job. A grant for a job a
	// person started lives the job's expected life (at most
	// MaxJobGrantLifetime); a standing grant's token lives at most an
	// hour. The same key signs the job-grant revocation list, under its
	// own typ. Root-signed like the receipt keys.
	PurposeJobGrant Purpose = "job-grant"
	// PurposeAuditCheckpoint signs checkpoints of an audit chain head. A
	// verifier checks one offline against the root-signed key set of
	// this purpose. It signs nothing else.
	PurposeAuditCheckpoint Purpose = "audit-checkpoint"

	// PurposeKeySetRoot is the offline root. It signs only
	// key-set resets. Online backends refuse to create it.
	PurposeKeySetRoot Purpose = "keyset-root"
)

// AllPurposes lists the ten online purposes.
func AllPurposes() []Purpose {
	return []Purpose{
		PurposeKubernetesIssuer, PurposeVPNLease, PurposeGate,
		PurposeOperationGrant, PurposePolicyBundle, PurposeAgentCA,
		PurposeEmergencyRoster, PurposeSvcMTLS, PurposeDecisionReceipt,
		PurposeJobGrant,
		PurposeAuditCheckpoint,
	}
}

// Valid reports whether p is a known purpose, online or root.
func (p Purpose) Valid() bool {
	if p == PurposeKeySetRoot {
		return true
	}
	for _, q := range AllPurposes() {
		if p == q {
			return true
		}
	}
	return false
}

// PrivilegedTokenLifetime caps a Kubernetes or gate token for a privileged
// group. token.Claims.Privileged selects it.
const PrivilegedTokenLifetime = 5 * time.Minute

// MaxTokenLifetime is the longest credential a key of this purpose signs.
// The VPN cap, the agent certificate lifetime and
// the Kubernetes and gate caps come from the spec. The
// operation-grant and policy-bundle values are draft values.
func (p Purpose) MaxTokenLifetime() time.Duration {
	switch p {
	case PurposeKubernetesIssuer:
		return 15 * time.Minute
	case PurposeVPNLease:
		return 8 * time.Hour // cap
	case PurposeGate:
		return 15 * time.Minute
	case PurposeOperationGrant:
		return 5 * time.Minute
	case PurposePolicyBundle:
		return 24 * time.Hour
	case PurposeAgentCA:
		return 24 * time.Hour // certificate lifetime
	case PurposeSvcMTLS:
		return 3 * 24 * time.Hour // certificate lifetime
	case PurposeDecisionReceipt:
		return MaxReceiptLifetime
	case PurposeJobGrant:
		return MaxJobGrantLifetime
	case PurposeAuditCheckpoint:
		// A checkpoint is not a token and never expires: it is evidence.
		// This value only sets the rotation overlap, so a verifier that
		// follows the key set sees the next key a day before first use.
		return 12 * time.Hour
	case PurposeEmergencyRoster:
		// A roster list is not a token and has no age cap (emergency
		// access must outlive an identity outage). This draft value
		// only sets the rotation overlap.
		return 24 * time.Hour
	}
	return 0
}

// MaxReceiptLifetime is the hard cap on a decision receipt: no
// setting raises it. roid's setting picks a shorter life (default 30 s,
// the read-permit cache bound).
const MaxReceiptLifetime = 60 * time.Second

// MaxJobGrantLifetime is the hard cap on a job grant: a job a person
// started may run a day at most. No setting raises it.
const MaxJobGrantLifetime = 24 * time.Hour

// RotationOverlap is the window: at least twice the longest token
// lifetime. The signer applies it on both sides of a rotation: the next
// key is published this long before first use, and a retired key stays
// published this long after last use.
func (p Purpose) RotationOverlap() time.Duration { return 2 * p.MaxTokenLifetime() }

// Rotates reports whether rotation applies. The existing agent CA
// never rotates.
func (p Purpose) Rotates() bool { return p != PurposeAgentCA && p != PurposeKeySetRoot }

// TokenType is the JOSE "typ" header value for objects of this purpose.
func (p Purpose) TokenType() string { return "runos." + string(p) + "+jwt" }

// Algorithm is a signing algorithm. RunOS tokens use EdDSA (Ed25519) and
// ES256 (P-256) only. RS256 exists only for roid's OIDC ID token key
// (OIDC Core makes RS256 mandatory). It is not on the
// allowlist, and SoftBackend never creates an RS256 key, so no RunOS
// purpose (Kubernetes issuer included) can hold one.
type Algorithm string

const (
	AlgEdDSA Algorithm = "EdDSA"
	AlgES256 Algorithm = "ES256"
	AlgRS256 Algorithm = "RS256"
)

// MinRSABits is the smallest RSA modulus an RS256 key may have.
const MinRSABits = 2048

// Allowed reports whether a is on the RunOS token allowlist.
func (a Algorithm) Allowed() bool { return a == AlgEdDSA || a == AlgES256 }
