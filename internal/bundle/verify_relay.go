package bundle

// The fresh token and the signed refusal of the relay transport (the
// relay claims). The applier only verifies them here. Roid signs them
// (seal_relay.go).

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The token classes and subjects of the two relay tokens (C3) are declared
// once, in seal_relay.go, so signer and verifier cannot drift.

// Errors of the relay tokens.
var (
	ErrFresh   = errors.New("bundle: fresh_token_mismatch")
	ErrRefusal = errors.New("bundle: bad_refusal")
)

// FreshTokenID is the token id (jti) of the fresh token for one applier
// nonce and one bundle content: hex(SHA-256("fresh" NUL nonce NUL
// contentDigest)). Only a signer that saw the nonce and the content can
// make a token with this id.
func FreshTokenID(nonce, contentDigest string) string {
	sum := sha256.Sum256([]byte("fresh\x00" + nonce + "\x00" + contentDigest))
	return hex.EncodeToString(sum[:])
}

// VerifyFresh checks a fresh token: signature under the pinned key set,
// audience (this cluster), expiry, class and subject, the account claim, and
// the id derived from the applier's own nonce and the content digest of the
// envelope it holds (Verified.Digest). No clock of the cluster is compared
// with a time inside the token beyond the usual leeway.
func (v *Verifier) VerifyFresh(tok, nonce, contentDigest string) error {
	if nonce == "" || contentDigest == "" {
		return fmt.Errorf("%w: no nonce or content digest", ErrFresh)
	}
	claims, err := v.tok.Verify(tok)
	if err != nil {
		return fmt.Errorf("bundle: fresh token: %w", err)
	}
	if claims.Class != relayClassFresh || claims.Subject != relaySubjectFresh {
		return fmt.Errorf("%w: not a fresh token", ErrFresh)
	}
	if err := v.checkTokenAccount(claims.Account); err != nil {
		return err
	}
	want := FreshTokenID(nonce, contentDigest)
	if subtle.ConstantTimeCompare([]byte(want), []byte(claims.ID)) != 1 {
		return fmt.Errorf("%w: not for this nonce and content", ErrFresh)
	}
	return nil
}

// VerifyRefusal checks roid's signed refusal and returns its reason
// ("cluster" or "retired"). Only a token that verifies and has not expired
// counts toward the applier's fail-safe.
func (v *Verifier) VerifyRefusal(tok string) (string, error) {
	claims, err := v.tok.Verify(tok)
	if err != nil {
		return "", fmt.Errorf("bundle: refusal: %w", err)
	}
	reason, ok := strings.CutPrefix(claims.Subject, relaySubjectRefusalBase)
	if claims.Class != relayClassRefusal || !ok || (reason != "cluster" && reason != "retired") {
		return "", fmt.Errorf("%w: not a refusal", ErrRefusal)
	}
	if err := v.checkTokenAccount(claims.Account); err != nil {
		return "", err
	}
	return reason, nil
}

// checkTokenAccount requires the account claim of a relay token, and the
// pinned account when the verifier has one.
func (v *Verifier) checkTokenAccount(acct string) error {
	if acct == "" || (v.account != "" && acct != v.account) {
		return ErrAccount
	}
	return nil
}
