package applier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/signer/token"
)

// The relay half of a pass.

// relayPrelude records what the status must say before any bundle is read:
// the labelled namespaces, and for an applier with no floor the fresh-start
// nonce. A change of either is written at once, so conductor sees
// needs_fresh and the nonce even while there is no bundle to read.
func (a *Applier) relayPrelude(ctx context.Context, ns []string, hasFloor bool) {
	a.info.Namespaces = slices.Clone(ns)
	slices.Sort(a.info.Namespaces)
	a.info.Namespaces = slices.Compact(a.info.Namespaces)
	a.info.NeedsFresh, a.info.FreshNonce = !hasFloor, ""
	if !hasFloor {
		a.info.FreshNonce = a.relay.Nonce()
	}
	a.report(ctx, a.lastStatus())
}

// lastStatus is the status last written, without its events (a repeat of
// them would count as news), or an empty one before the first write.
func (a *Applier) lastStatus() Status {
	if !a.hasSent {
		return Status{AppliedAt: a.Now()}
	}
	last := a.sent
	last.Events = nil
	return last
}

// relayFetch returns the envelope to act on. When the bundle ConfigMap has
// not moved since an envelope verified, that envelope is used again without
// a read or a verify. Otherwise it reads, rebuilds and verifies. The
// status to report for a bundle that does not verify comes with the error.
func (a *Applier) relayFetch(ctx context.Context, ns []string, fresh bool, fail func(uint64, string, error) (*Status, error)) (bundle.Verified, bool, *Status, error) {
	if rev, err := a.relay.Revision(ctx); err == nil && a.verifiedRV != "" && rev.Bundle == a.verifiedRV {
		reason, err := a.relay.Refusal(ctx)
		if err != nil {
			return bundle.Verified{}, false, nil, fmt.Errorf("applier: fetch: %w", err)
		}
		if reason != "" {
			return bundle.Verified{}, false, nil, fmt.Errorf("applier: fetch: %w: signed refusal: %s", ErrRoidRefused, reason)
		}
		return a.verifiedV, true, nil, nil
	}
	raw, err := a.relay.Fetch(ctx, ns, fresh)
	if err != nil {
		if errors.Is(err, bundle.ErrTooLarge) || errors.Is(err, bundle.ErrFormat) {
			a.verifiedRV = ""
			a.info.VerifyError = verifyClass(err)
			st, err := fail(0, "", err)
			return bundle.Verified{}, false, st, err
		}
		return bundle.Verified{}, false, nil, fmt.Errorf("applier: fetch: %w", err)
	}
	v, err := a.Verifier.Verify(raw)
	if err != nil {
		a.verifiedRV = ""
		a.info.VerifyError = verifyClass(err)
		st, err := fail(0, "", err)
		return bundle.Verified{}, false, st, err
	}
	sum := sha256.Sum256(raw)
	a.verifiedRV, a.verifiedV = a.relay.FetchedRevision(), v
	a.info.VerifyError, a.info.SeenEnvelopeSHA256, a.info.LastIssuedAt = "", hex.EncodeToString(sum[:]), v.IssuedAt
	return v, false, nil, nil
}

// checkFresh requires the fresh token that came with the envelope to be
// roid's, for this process's nonce and this envelope's content.
func (a *Applier) checkFresh(v bundle.Verified) error {
	if err := a.Verifier.VerifyFresh(a.relay.FreshToken(), a.relay.Nonce(), v.Digest); err != nil {
		return fmt.Errorf("%w: an applier with no floor applies a bundle only with a fresh token for its own nonce: %v", bundle.ErrStale, err)
	}
	return nil
}

// verifyClass is the short class of a verify failure, for the status. A bad
// node clock shows as not_yet_valid or expired.
func verifyClass(err error) string {
	for _, c := range []struct {
		err  error
		code string
	}{
		{bundle.ErrDigest, "digest_mismatch"}, {bundle.ErrCluster, "wrong_cluster"}, {bundle.ErrAccount, "wrong_account"},
		{bundle.ErrSubject, "not_an_rbac_bundle"}, {bundle.ErrTooLarge, "too_large"}, {bundle.ErrFormat, "bad_format"},
	} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return token.Code(err)
}

// RunRelay runs the relay loop: every watch interval it reads the metadata
// of the bundle and relay ConfigMaps, and a changed resourceVersion starts a
// pass now. Otherwise a pass runs every interval, which keeps the drift
// repair and the canary going. A pass at start.
func (a *Applier) RunRelay(ctx context.Context, watch, every time.Duration, onPass func(Result, error)) {
	if a.relay == nil {
		a.relay, _ = a.Roid.(RelayRoid)
	}
	if a.relay == nil {
		a.Run(ctx, every, onPass)
		return
	}
	t := time.NewTicker(watch)
	defer t.Stop()
	var (
		seen     Revision
		lastPass time.Time
	)
	for {
		rev, rerr := a.relay.Revision(ctx)
		if lastPass.IsZero() || a.Now().Sub(lastPass) >= every || (rerr == nil && rev != seen) {
			if rerr == nil {
				seen = rev
			}
			res, err := a.RunOnce(ctx)
			lastPass = a.Now()
			if onPass != nil {
				onPass(res, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
