package bundle

// The two extra tokens roid signs on the relay path. Both use the
// policy-bundle key, the bundle issuer and a 15 minute life, and both
// name one cluster and one account.
//
//   - The fresh token answers the nonce an applier chose at start. Its id is
//     the SHA-256 of "fresh", the nonce and the content digest of the
//     envelope served with it, so a replayed older envelope never matches.
//     No clock of the cluster takes part.
//   - The refusal token says roid refuses the cluster ("cluster", or
//     "retired" after a confirmed retire). Only a verified, unexpired
//     refusal counts toward the applier's 24 hour fail-safe.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/token"
)

// Token fields of the relay tokens (C3).
const (
	relayClassFresh         = "k8s-rbac-fresh"
	relaySubjectFresh       = "k8s-rbac-fresh"
	relayClassRefusal       = "k8s-rbac-refusal"
	relaySubjectRefusalBase = "k8s-rbac-refusal:"
)

// relayTokenTTL is the life of a fresh token and of a refusal token.
const relayTokenTTL = 15 * time.Minute

// ErrRelaySeal is returned when a relay token cannot be signed for the
// input given.
var ErrRelaySeal = errors.New("bundle: relay token input")

// FreshID is the id of the fresh token for a nonce and a content digest:
// hex(SHA-256("fresh" 0x00 nonce 0x00 contentDigest)).
func FreshID(nonce, contentDigest string) string {
	h := sha256.New()
	h.Write([]byte("fresh\x00"))
	h.Write([]byte(nonce))
	h.Write([]byte{0})
	h.Write([]byte(contentDigest))
	return hex.EncodeToString(h.Sum(nil))
}

// SealFresh signs the fresh token of an applier's nonce for the envelope
// whose ContentDigest is contentDigest.
func SealFresh(ctx context.Context, issuer *token.Issuer, account, cluster, nonce, contentDigest string) (string, error) {
	if account == "" || cluster == "" || nonce == "" || contentDigest == "" {
		return "", fmt.Errorf("%w: fresh token needs an account, a cluster, a nonce and a content digest", ErrRelaySeal)
	}
	tok, err := issuer.Issue(ctx, signer.PurposePolicyBundle, token.Claims{
		Claims: jwt.Claims{Subject: relaySubjectFresh, ID: FreshID(nonce, contentDigest), Audience: jwt.Audience{Audience(cluster)}},
		Class:  relayClassFresh, Account: account,
	}, relayTokenTTL)
	if err != nil {
		return "", fmt.Errorf("bundle: sign fresh: %w", err)
	}
	return tok, nil
}

// SealRefusal signs the refusal of a cluster for an account. reason is
// "cluster" or "retired". The id is random, so every refusal differs.
func SealRefusal(ctx context.Context, issuer *token.Issuer, account, cluster, reason string) (string, error) {
	if account == "" || cluster == "" || (reason != "cluster" && reason != "retired") {
		return "", fmt.Errorf("%w: refusal needs an account, a cluster and the reason cluster or retired", ErrRelaySeal)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	tok, err := issuer.Issue(ctx, signer.PurposePolicyBundle, token.Claims{
		Claims: jwt.Claims{Subject: relaySubjectRefusalBase + reason, ID: hex.EncodeToString(id[:]), Audience: jwt.Audience{Audience(cluster)}},
		Class:  relayClassRefusal, Account: account,
	}, relayTokenTTL)
	if err != nil {
		return "", fmt.Errorf("bundle: sign refusal: %w", err)
	}
	return tok, nil
}
