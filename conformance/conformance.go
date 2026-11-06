// Package conformance is the frozen set of signed test vectors that the
// signing side (RunOS's identity service) and the verifying side (this
// repository) agree on, and the code that runs them.
//
// The vectors are in testdata/conformance/vectors.json. Each case is one
// object that a verifier is given, and the outcome it must reach: accepted
// with these facts, or refused with this error code. The file also holds the
// pinned trust (the offline root public key and the signed key set) and a
// fixed clock, so a case needs nothing else to run.
//
// Every key behind the vectors is a TEST-ONLY key. Its seed is derived from a
// public label, so nobody must ever trust it in a real cluster. The file holds
// public keys and signed tokens only.
//
// A case never changes after release. When a release changes what a verifier
// decides, a new file (vectors-v2.json) is added next to the old one and the
// old one keeps passing, or the release says in its changelog that an old
// verdict changed. See docs/conformance.md.
package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/signer/token"
)

// Case kinds.
const (
	// KindBundle: Envelope goes to bundle.Verifier.Verify.
	KindBundle = "bundle"
	// KindFresh: Token, Nonce and ContentDigest go to VerifyFresh.
	KindFresh = "fresh"
	// KindRefusal: Token goes to VerifyRefusal.
	KindRefusal = "refusal"
	// KindKeySet: Signed, a root-signed key set, goes to UpdateKeys.
	KindKeySet = "keyset"
)

// File is the content of vectors.json.
type File struct {
	Format int    `json:"format"`
	Notice string `json:"notice"`
	// Clock is the time every case runs at, unless the case sets Now.
	Clock time.Time `json:"clock"`
	// Account is the account every verifier expects, unless the case sets one.
	Account string `json:"account"`
	// Trust is what a verifier pins: the issuer, the cluster, the offline root
	// public key and the root-published key set.
	Trust bundle.Trust `json:"trust"`
	Cases []Case       `json:"cases"`
}

// Case is one vector.
type Case struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Description string `json:"description"`

	// Now overrides the clock of the file. Cluster overrides the cluster in
	// the trust. Account overrides the expected account.
	Now     *time.Time `json:"now,omitempty"`
	Cluster string     `json:"cluster,omitempty"`
	Account string     `json:"account,omitempty"`

	Envelope      *bundle.Envelope `json:"envelope,omitempty"`
	Token         string           `json:"jws,omitempty"`
	Nonce         string           `json:"nonce,omitempty"`
	ContentDigest string           `json:"content_digest,omitempty"`
	Signed        string           `json:"signed,omitempty"`

	Expect Expect `json:"expect"`
}

// Expect is the outcome a verifier must reach.
type Expect struct {
	OK bool `json:"ok"`
	// Error is the code of the refusal (see Code) when OK is false.
	Error string `json:"error,omitempty"`
	// Version and ContentDigest are the facts of an accepted bundle.
	Version       uint64 `json:"version,omitempty"`
	ContentDigest string `json:"content_digest,omitempty"`
	// Reason is the reason of an accepted refusal token.
	Reason string `json:"reason,omitempty"`
}

// Load reads and parses a vector file.
func Load(path string) (File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return File{}, fmt.Errorf("conformance: %s: %w", path, err)
	}
	if f.Format != 1 {
		return File{}, fmt.Errorf("conformance: %s: format %d, this code reads format 1", path, f.Format)
	}
	return f, nil
}

// Code is the stable name of a refusal, the same for every implementation.
// Errors of the bundle package keep their own names; every other error is a
// token error and takes the code of token.Code.
func Code(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, bundle.ErrFormat):
		return "bad_format"
	case errors.Is(err, bundle.ErrSubject):
		return "not_an_rbac_bundle"
	case errors.Is(err, bundle.ErrDigest):
		return "digest_mismatch"
	case errors.Is(err, bundle.ErrCluster):
		return "wrong_cluster"
	case errors.Is(err, bundle.ErrAccount):
		return "wrong_account"
	case errors.Is(err, bundle.ErrFresh):
		return "fresh_token_mismatch"
	case errors.Is(err, bundle.ErrRefusal):
		return "bad_refusal"
	}
	return token.Code(err)
}

// NewVerifier builds the verifier for one case: the pinned trust of the file
// (with the cluster of the case), the clock of the case, and the expected
// account. stateDir is a scratch directory the verifier writes its state to.
func (f File) NewVerifier(c Case, stateDir string) (*bundle.Verifier, error) {
	trust := f.Trust
	if c.Cluster != "" {
		trust.Cluster = c.Cluster
	}
	now := f.Clock
	if c.Now != nil {
		now = *c.Now
	}
	v, err := bundle.NewVerifier(trust, func() time.Time { return now }, filepath.Join(stateDir, "root-chain.json"))
	if err != nil {
		return nil, err
	}
	account := f.Account
	if c.Account != "" {
		account = c.Account
	}
	v.ExpectAccount(account)
	return v, nil
}

// Run gives the case to a fresh verifier and returns what happened: the
// refusal code ("" when accepted) and the facts of an accepted case.
func (f File) Run(c Case, stateDir string) (Expect, error) {
	v, err := f.NewVerifier(c, stateDir)
	if err != nil {
		return Expect{}, fmt.Errorf("conformance: %s: build verifier: %w", c.ID, err)
	}
	var got Expect
	var verr error
	switch c.Kind {
	case KindBundle:
		if c.Envelope == nil {
			return Expect{}, fmt.Errorf("conformance: %s: a bundle case needs an envelope", c.ID)
		}
		raw, err := json.Marshal(c.Envelope)
		if err != nil {
			return Expect{}, err
		}
		var ver bundle.Verified
		ver, verr = v.Verify(raw)
		if verr == nil {
			got.Version, got.ContentDigest = ver.Bundle.Version, ver.Digest
		}
	case KindFresh:
		verr = v.VerifyFresh(c.Token, c.Nonce, c.ContentDigest)
	case KindRefusal:
		got.Reason, verr = v.VerifyRefusal(c.Token)
	case KindKeySet:
		verr = v.UpdateKeys(c.Signed)
	default:
		return Expect{}, fmt.Errorf("conformance: %s: unknown kind %q", c.ID, c.Kind)
	}
	got.OK, got.Error = verr == nil, Code(verr)
	return got, nil
}

// Check runs the case and returns an error when the outcome is not the one
// the file expects.
func (f File) Check(c Case, stateDir string) error {
	got, err := f.Run(c, stateDir)
	if err != nil {
		return err
	}
	if got != c.Expect {
		return fmt.Errorf("conformance: %s: got %+v, the file expects %+v", c.ID, got, c.Expect)
	}
	return nil
}
