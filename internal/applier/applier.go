// Package applier is the in-cluster side of the RBAC projection. It pulls
// the cluster's signed bundle from roid over the cluster's service
// certificate, verifies it against the pinned key set, refuses anything
// below its durable floor, and applies it with the reconciler: the deny
// list first, then removals, then creates and repairs. It removes only
// objects it owns (the runos.com/roid-managed label) and hand-made bindings
// that name a runos subject, and it reports every pass back to roid.
//
// The pull runs in the cluster, so a grant or a revoke in roid never waits
// on conductor.
package applier

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/runos-official/rolekeeper/internal/bundle"
	"github.com/runos-official/rolekeeper/internal/compile"
	"github.com/runos-official/rolekeeper/internal/kobj"
	"github.com/runos-official/rolekeeper/internal/kubeapi"
	"github.com/runos-official/rolekeeper/internal/reconcile"
)

// Roid is the applier's view of roid's service listener.
type Roid interface {
	// Fetch returns the bundle envelope for the managed namespaces. fresh
	// asks roid to sign a new envelope instead of a cached one.
	Fetch(ctx context.Context, namespaces []string, fresh bool) ([]byte, error)
	// Report sends the result of one pass.
	Report(ctx context.Context, s Status) error
}

// KeySetSource is a Roid that also serves the newest root-signed
// policy-bundle key set (GET /v1/keysets/policy-bundle).
type KeySetSource interface {
	KeySet(ctx context.Context, purpose string) (string, error)
}

// KeySetStore keeps the root-signed key set the applier follows, so a
// restart never trusts a key a reset removed (ConfigMapKeySets).
type KeySetStore interface {
	Load(ctx context.Context) (string, bool, error)
	Store(ctx context.Context, signed string) error
}

// Status is the result of one pass, as roid stores and audits it.
type Status struct {
	Version   uint64         `json:"version"`
	Digest    string         `json:"digest,omitempty"`
	Applied   bool           `json:"applied"`
	DenyOnly  bool           `json:"deny_only,omitempty"`
	Events    map[string]int `json:"events,omitempty"`
	Error     string         `json:"error,omitempty"`
	AppliedAt time.Time      `json:"applied_at"`
	// PassMS is how long the pass took, from the fetch to the last write.
	PassMS int64 `json:"pass_ms"`
	// Canary is the result of the deny canary check: CanaryOK,
	// CanaryFailing, or empty when the check is off. CanaryReason says
	// what failed.
	Canary       string `json:"canary,omitempty"`
	CanaryReason string `json:"canary_reason,omitempty"`
	// Retired says the applier removed every object it manages and
	// stopped. FailSafe says the local fail-safe did it, not a
	// retire bundle.
	Retired  bool `json:"retired,omitempty"`
	FailSafe bool `json:"fail_safe,omitempty"`
}

// Canary check results.
const (
	// CanaryOK: the API server refused the listed canary and let the other
	// one write, so the deny list cuts and the policy sees its changes.
	CanaryOK = "ok"
	// CanaryFailing: one of the two answers was wrong for longer than the
	// grace. A person on the deny list may still be able to write.
	CanaryFailing = "failing"
)

// CanaryProbe is the API server side of the canary check
// (kubeapi.Client.DenyProbe): a dry-run write as one canary user.
type CanaryProbe interface {
	DenyProbe(ctx context.Context, user, ns string) (kubeapi.ProbeResult, string, error)
}

// Applier runs passes for one cluster.
type Applier struct {
	Verifier *bundle.Verifier
	Floor    bundle.FloorStore
	Roid     Roid
	Kube     reconcile.Kube
	Sink     reconcile.Sink
	// Namespaces lists the namespaces RunOS manages in this cluster.
	Namespaces func(ctx context.Context) ([]string, error)
	Now        func() time.Time
	// Started is when this process started. A fresh applier (no floor
	// stored) accepts only a bundle signed at or after Started.
	Started time.Time
	// ReportEvery is the heartbeat: a pass that changed nothing and has
	// the status last sent is reported again only after this long
	// (default 5 minutes). Any change or refusal is reported at once.
	ReportEvery time.Duration

	// Probe, when set, runs the deny canary check after every pass: one
	// of two reserved canaries is kept on the deny list, and the API
	// server must refuse a dry-run write by it and allow one by the
	// other. CanaryNamespace is where the dry-run ConfigMap would go.
	Probe           CanaryProbe
	CanaryNamespace string
	// CanaryEvery is how often the canary on the list turns over (default
	// 30 s). A re-created policy can keep an old copy of its list, so only a
	// canary that moves finds it. CanaryGrace is how long a wrong answer
	// may last before it counts (default 10 s): the API server sees a list
	// change a moment after it is written.
	CanaryEvery time.Duration
	CanaryGrace time.Duration

	// KeySets, when set, keeps the policy-bundle key set the applier
	// follows from roid. Before each pass
	// the applier applies the newest root-signed set roid serves, so a
	// compromise reset stops bundles the removed key signed.
	KeySets KeySetStore
	// RefusedBound is the local fail-safe: when roid refused this
	// applier (ErrRoidRefused) on every fetch for longer than this, with no
	// bundle in between, the applier removes every object it manages.
	// Default 24 hours. An unreachable roid never counts.
	RefusedBound time.Duration
	// RetiredEvery is how often a retired applier asks roid again
	// (default 10 minutes). A newer signed bundle resumes it.
	RetiredEvery time.Duration

	keysLoaded bool
	// keysStored is the key set the store holds as far as this process
	// knows. A pass writes the verifier's set again while they differ, so
	// one failed write is retried until it lands.
	keysStored string

	rec *reconcile.Reconciler
	// retired: this applier removed what it manages and stopped.
	// floorRead says the stored floor was read once for its retired mark.
	retired     bool
	floorRead   bool
	retiredPoll time.Time
	// refusedSince is the first of an unbroken run of roid refusals
	// (ErrRoidRefused) with no fetched bundle in between; zero when none.
	refusedSince time.Time
	fetched      bool // the last pass got an envelope from roid
	// stale: the last pass got a verified envelope below the floor this
	// applier holds. A run of those counts toward the fail-safe like a
	// refusal: roid serves this cluster, but not at a version
	// that can replace the bindings held.
	stale bool
	// applied is the floor this process stored last. A floor
	// ConfigMap deleted or lowered while the applier runs never lets a
	// bundle below it back in, and the store gets it back.
	applied    bundle.Floor
	hasApplied bool
	sent       Status
	sentAt     time.Time
	hasSent    bool
	passFrom   time.Time
	// lastDeny holds the deny objects of the last applied bundle, to write
	// a missing list back when no new bundle can be had.
	lastDeny []kobj.Object

	// relay is the Roid when it lives in the cluster (ROID_K8S_TRANSPORT=
	// relay); nil for the pull transport. The relay state below is used only
	// then.
	relay RelayRoid
	info  RelayInfo
	// sentInfo is the relay info of the last status written.
	sentInfo RelayInfo
	// verifiedRV is the resourceVersion of the bundle ConfigMap whose
	// envelope verified; verifiedV is that envelope's content. A pass whose
	// bundle ConfigMap has not moved reconciles with them and does not read
	// or verify again: the bundle token expires 15 minutes after signing,
	// and a verified, applied envelope must not start to fail with it.
	verifiedRV string
	verifiedV  bundle.Verified
	// delivered: this pass verified a newly delivered envelope at or above
	// the floor. Only that resets the fail-safe run in the relay.
	delivered bool

	canaryWant   string // the canary the next pass puts on the list
	canaryTurned time.Time
	canaryFail   time.Time // first wrong answer of the current run, or zero
	canaryState  string
	canaryReason string
}

// Result is one pass.
type Result struct {
	Version uint64
	Applied bool
	Report  reconcile.Report
	// Canary is the canary state after the pass (Status.Canary).
	Canary       string
	CanaryReason string
	// Retired: the applier holds no grants on the cluster and has
	// stopped. FailSafe: the local fail-safe retired it in this pass.
	Retired  bool
	FailSafe bool
	// Lagging: the bundle names other namespaces than the cluster labels
	// as managed, so only its deny list was applied.
	Lagging bool
}

// ErrRoidRefused is roid's answer that it does not serve this applier:
// 403 k8s.not_allowed on the service listener, over the pinned TLS. It is
// the only answer that counts toward the fail-safe.
var ErrRoidRefused = errors.New("applier: roid refused this applier")

// RunOnce fetches, verifies and applies one bundle. Every check runs
// before the first write. When the pass stops before the apply (roid
// unreachable, a refused bundle), a missing deny list is still written
// back from the last applied bundle. The canary check runs after either.
func (a *Applier) RunOnce(ctx context.Context) (Result, error) {
	if a.rec == nil {
		// The installer owns the deny policy and its binding: the applier
		// keeps them in place and never creates or deletes them.
		a.rec = &reconcile.Reconciler{Kube: a.Kube, Sink: a.Sink, Now: a.Now, KeepDenyPolicy: true}
	}
	if a.relay == nil {
		a.relay, _ = a.Roid.(RelayRoid)
	}
	a.passFrom = time.Now()
	a.fetched, a.stale, a.delivered = false, false, false
	if !a.floorRead {
		if f, ok, err := a.Floor.Load(ctx); err == nil {
			a.floorRead, a.retired = true, ok && f.Retired
		}
	}
	if a.retired {
		return a.retiredPass(ctx)
	}
	a.prepareCanary(ctx)
	var (
		res     Result
		st      *Status
		applied bool
		err     error
	)
	if kerr := a.followKeys(ctx); kerr != nil {
		// An unreadable key-set store fails the pass, as an unreadable
		// floor does: the install pin may still hold a removed key.
		err = kerr
		st = &Status{Error: err.Error(), AppliedAt: a.Now()}
	} else {
		res, st, applied, err = a.pass(ctx)
	}
	if a.retired {
		// A retire bundle applied: report it and stop. No canary and
		// no deny list repair from here on.
		if st != nil {
			a.report(ctx, *st)
		}
		res.Retired = true
		return res, err
	}
	if fired, fres, ferr := a.failSafe(ctx, err); fired {
		return fres, ferr
	}
	if !applied && a.lastDeny != nil {
		rep, rerr := a.rec.RepairDenyList(ctx, a.lastDeny)
		res.Report.Events = append(res.Report.Events, rep.Events...)
		if rerr != nil && err == nil {
			err = rerr
		}
		if len(rep.Events) > 0 {
			if st == nil {
				st = &Status{Version: res.Version, Error: err.Error(), AppliedAt: a.Now()}
			}
			st.Events = counts(res.Report)
		}
	}
	changed := a.checkCanary(ctx)
	res.Canary, res.CanaryReason = a.canaryState, a.canaryReason
	if st == nil && changed && err != nil {
		st = &Status{Version: res.Version, Error: err.Error(), AppliedAt: a.Now()}
	}
	if st == nil && a.relay != nil {
		// In the relay the status ConfigMap is how conductor sees this
		// applier at all, so the heartbeat and the relay fields go out even
		// when the pass had nothing to report (no bundle yet, a missing
		// ConfigMap): the last status stands, with the new fields.
		last := a.lastStatus()
		st = &last
	}
	if st != nil {
		st.Canary, st.CanaryReason = a.canaryState, a.canaryReason
		a.report(ctx, *st) // a lost report never undoes an applied bundle
	}
	return res, err
}

// pass is one fetch, verify and apply. It returns the status to report
// (nil for a failed fetch: roid is not there to hear it) and whether the
// bundle reached the reconciler.
func (a *Applier) pass(ctx context.Context) (Result, *Status, bool, error) {
	fail := func(version uint64, digest string, err error) (*Status, error) {
		return &Status{Version: version, Digest: digest, Error: err.Error(), AppliedAt: a.Now()}, err
	}
	stored, hasFloor, err := a.Floor.Load(ctx)
	if err != nil {
		st, err := fail(0, "", fmt.Errorf("applier: floor unreadable: %w", err))
		return Result{}, st, false, err
	}
	if a.hasApplied && (!hasFloor || stored.Version < a.applied.Version) {
		// The stored floor went missing or moved back under a running
		// applier: write back the one this process applied.
		if err := a.Floor.Store(ctx, a.applied); err != nil {
			st, err := fail(0, "", fmt.Errorf("applier: floor below the applied v%d and not restored: %w", a.applied.Version, err))
			return Result{}, st, false, err
		}
		hasFloor = true
	}
	ns, err := a.Namespaces(ctx)
	if err != nil {
		st, err := fail(0, "", fmt.Errorf("applier: list managed namespaces: %w", err))
		return Result{}, st, false, err
	}
	a.fetched = false
	var (
		v      bundle.Verified
		fromRV bool // v is the envelope that verified before, not a new read
	)
	if a.relay != nil {
		a.relayPrelude(ctx, ns, hasFloor)
		var rst *Status
		v, fromRV, rst, err = a.relayFetch(ctx, ns, !hasFloor, fail)
		if err != nil {
			return Result{}, rst, false, err
		}
	} else {
		raw, err := a.Roid.Fetch(ctx, ns, !hasFloor)
		if err != nil {
			return Result{}, nil, false, fmt.Errorf("applier: fetch: %w", err)
		}
		a.fetched = true
		if v, err = a.Verifier.Verify(raw); err != nil {
			st, err := fail(0, "", err)
			return Result{}, st, false, err
		}
		if !hasFloor && v.IssuedAt.Before(a.Started.Truncate(time.Second)) {
			st, err := fail(v.Bundle.Version, v.Digest, fmt.Errorf("%w: a fresh applier refuses a bundle signed before it started", bundle.ErrStale))
			return Result{Version: v.Bundle.Version}, st, false, err
		}
	}
	b := v.Bundle
	if a.relay != nil && !hasFloor {
		// No floor: the first bundle needs a fresh token for this process's
		// nonce and this content, in place of the pull transport's "signed
		// after I started".
		if err := a.checkFresh(v); err != nil {
			a.info.VerifyError = "fresh_required"
			st, err := fail(b.Version, v.Digest, err)
			return Result{Version: b.Version}, st, false, err
		}
	}
	err = bundle.CheckFloor(ctx, a.Floor, b.Version, v.Digest)
	if err == nil && a.hasApplied {
		err = bundle.CheckFloorValue(a.applied, b.Version, v.Digest)
	}
	if err != nil {
		a.stale = hasFloor && errors.Is(err, bundle.ErrStale)
		if a.stale && a.relay != nil && fromRV {
			a.stale = false // the cached envelope is not a new delivery
		}
		st, err := fail(b.Version, v.Digest, err)
		return Result{Version: b.Version}, st, false, err
	}
	if a.relay != nil {
		// A delivery: a newly read, verified envelope at or above the floor.
		// The cached envelope of a skipped read is not one.
		a.fetched = !fromRV
	}
	managed := b.Namespaces
	if b.Retire {
		// A retire bundle is a pure reduction: the deny list and nothing
		// else. The prune then removes every object this applier
		// manages, in every namespace either side knows of.
		if err := checkRetire(b); err != nil {
			st, err := fail(b.Version, v.Digest, err)
			return Result{Version: b.Version}, st, false, err
		}
		managed = union(b.Namespaces, ns)
	}
	// A bundle that is too large for the relay is a deny-only bundle.
	denyOnly := b.DenyOnly || b.TooLarge
	if !b.Retire && !denyOnly && !sameNamespaces(b.Namespaces, ns) {
		// The bundle names other managed namespaces than this cluster
		// labels: an empty bundle, a stale list, namespaces the
		// cluster never labelled. Only its deny list is applied. Nothing is
		// removed and the floor does not move; the next status carries the
		// labelled set, and roid answers with the matching bundle.
		return a.laggingPass(ctx, b, v, fail)
	}
	a.info.Lagging = false
	out := compile.Output{PolicyVersion: b.PolicyVersion, Objects: b.Objects, DenyOnly: denyOnly}
	rep, err := a.rec.Pass(ctx, out, managed)
	if err != nil && !errors.Is(err, reconcile.ErrRefused) {
		st, err := fail(b.Version, v.Digest, err)
		st.Events = counts(rep)
		// A lint refusal writes nothing but a clean deny list; any
		// other error may have stopped after the deny list, and the repair
		// below only fills a gap.
		return Result{Version: b.Version, Report: rep}, st, false, err
	}
	// A deny-only bundle applied as intended: the floor moves, and the
	// status says only the deny list changed.
	a.applied, a.hasApplied = bundle.Floor{Version: b.Version, Digest: v.Digest, Retired: b.Retire}, true
	a.retired, a.retiredPoll = b.Retire, a.Now()
	if err := a.Floor.Store(ctx, a.applied); err != nil {
		st, err := fail(b.Version, v.Digest, fmt.Errorf("applier: floor not durable: %w", err))
		st.Retired = b.Retire
		return Result{Version: b.Version, Report: rep}, st, true, err
	}
	a.info.NeedsFresh, a.info.FreshNonce = false, ""
	a.lastDeny = a.lastDeny[:0]
	for _, o := range b.Objects {
		if compile.IsKeptDenyObject(o.Kind, o.Name) || (o.Kind == kobj.KindConfigMap && o.Name == compile.DenyPolicyName && o.Namespace == compile.DenyNamespace) {
			a.lastDeny = append(a.lastDeny, o)
		}
	}
	st := &Status{Version: b.Version, Digest: v.Digest, Applied: true, DenyOnly: denyOnly, Retired: b.Retire, Events: counts(rep), AppliedAt: a.Now()}
	return Result{Version: b.Version, Applied: true, Retired: b.Retire, Report: rep}, st, true, nil
}

// sameNamespaces reports whether the bundle's managed namespaces are the
// cluster's labelled ones (both compared sorted and without duplicates).
func sameNamespaces(bundleNS, labelled []string) bool {
	norm := func(in []string) []string {
		out := slices.Clone(in)
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(norm(bundleNS), norm(labelled))
}

// laggingPass applies the deny list of a bundle that lags and
// nothing else.
func (a *Applier) laggingPass(ctx context.Context, b bundle.Bundle, v bundle.Verified, fail func(uint64, string, error) (*Status, error)) (Result, *Status, bool, error) {
	a.info.Lagging = true
	rep, err := a.rec.PassDenyListOnly(ctx, compile.Output{PolicyVersion: b.PolicyVersion, Objects: b.Objects})
	if err != nil {
		st, err := fail(b.Version, v.Digest, err)
		st.Events = counts(rep)
		return Result{Version: b.Version, Report: rep, Lagging: true}, st, false, err
	}
	a.lastDeny = reconcile.DenyObjects(b.Objects)
	st := &Status{Version: b.Version, Digest: v.Digest, DenyOnly: true, Events: counts(rep), AppliedAt: a.Now()}
	return Result{Version: b.Version, Report: rep, Lagging: true}, st, false, nil
}

// checkRetire refuses a retire bundle that holds anything but the deny
// list objects, or that is also marked deny-only.
func checkRetire(b bundle.Bundle) error {
	if b.DenyOnly {
		return fmt.Errorf("%w: a retire bundle is not deny-only", bundle.ErrFormat)
	}
	for _, o := range b.Objects {
		if !compile.IsKeptDenyObject(o.Kind, o.Name) && !(o.Kind == kobj.KindConfigMap && o.Name == compile.DenyPolicyName && o.Namespace == compile.DenyNamespace) {
			return fmt.Errorf("%w: a retire bundle holds %s; it may hold the deny list only", bundle.ErrFormat, o.Key())
		}
	}
	return nil
}

func union(a, b []string) []string {
	out := append(append([]string{}, a...), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

// retiredPass is a pass of a retired applier: it asks roid again only
// every RetiredEvery, writes nothing unless a newer signed bundle arrives,
// and treats roid's refusal as the expected answer.
func (a *Applier) retiredPass(ctx context.Context) (Result, error) {
	every := a.RetiredEvery
	if every <= 0 {
		every = 10 * time.Minute
	}
	if !a.retiredPoll.IsZero() && a.Now().Sub(a.retiredPoll) < every {
		return Result{Retired: true}, nil
	}
	a.retiredPoll = a.Now()
	if a.rec == nil {
		a.rec = &reconcile.Reconciler{Kube: a.Kube, Sink: a.Sink, Now: a.Now, KeepDenyPolicy: true}
	}
	if err := a.followKeys(ctx); err != nil {
		return Result{Retired: true}, err
	}
	res, st, applied, err := a.pass(ctx)
	if !applied {
		res.Retired = true
		if errors.Is(err, ErrRoidRefused) {
			return res, nil
		}
		return res, err
	}
	res.Retired = a.retired
	if !a.retired {
		a.refusedSince = time.Time{}
	}
	if st != nil {
		a.report(ctx, *st)
	}
	return res, err
}

// failSafe tracks roid's refusals and, past RefusedBound, removes every
// object this applier manages. Two answers count: ErrRoidRefused
// (roid answered over the pinned TLS that it does not serve this applier
// for this cluster) and a verified envelope below the floor (roid
// serves the cluster, but never at a version that replaces what this
// applier holds). An unreachable roid (network, 5xx, 429, 401, 3xx)
// neither counts nor resets the clock; any other fetched envelope resets
// it. The removal keeps the floor and
// marks it retired, so a later bundle at or above the floor, signed by
// roid, restores access: a mistaken fail-safe heals once roid answers.
func (a *Applier) failSafe(ctx context.Context, passErr error) (bool, Result, error) {
	now := a.Now()
	switch {
	case a.fetched && !a.stale:
		a.refusedSince = time.Time{}
		return false, Result{}, nil
	case !a.stale && !errors.Is(passErr, ErrRoidRefused):
		return false, Result{}, nil
	case a.refusedSince.IsZero():
		a.refusedSince = now
		return false, Result{}, nil
	}
	bound := a.RefusedBound
	if bound <= 0 {
		bound = 24 * time.Hour
	}
	if now.Sub(a.refusedSince) < bound {
		return false, Result{}, nil
	}
	ns, err := a.Namespaces(ctx)
	if err != nil {
		return true, Result{}, fmt.Errorf("applier: fail-safe: list managed namespaces: %w", err)
	}
	// No objects: the prune removes every managed object and every
	// hand-made runos binding; the deny policy, its binding and its list
	// are never removed.
	rep, err := a.rec.Pass(ctx, compile.Output{PolicyVersion: "fail-safe"}, ns)
	if err != nil {
		return true, Result{Report: rep}, fmt.Errorf("applier: fail-safe: %w", err)
	}
	f, ok, ferr := a.Floor.Load(ctx)
	if ferr == nil && ok {
		f.Retired = true
		if ferr = a.Floor.Store(ctx, f); ferr == nil {
			a.applied, a.hasApplied = f, true
		}
	}
	a.retired, a.retiredPoll = true, now
	st := Status{Version: a.applied.Version, Digest: a.applied.Digest, Applied: true, Retired: true, FailSafe: true,
		Events: counts(rep), AppliedAt: now, Error: "roid refused this applier (or served only stale bundles) since " + a.refusedSince.UTC().Format(time.RFC3339)}
	a.report(ctx, st) // roid refuses it too; the attempt is the record
	if ferr != nil {
		ferr = fmt.Errorf("applier: fail-safe: retired mark not durable: %w", ferr)
	}
	return true, Result{Version: a.applied.Version, Applied: true, Retired: true, FailSafe: true, Report: rep}, ferr
}

// followKeys loads the stored key set once, then applies the newest one
// roid serves. It writes the verifier's set to the store whenever the
// store does not hold it yet, so a failed write is retried every pass. A
// store that cannot be read at start fails the pass; roid being
// unreachable or a failed write keeps the keys the verifier holds.
func (a *Applier) followKeys(ctx context.Context) error {
	if a.KeySets == nil {
		return nil
	}
	if !a.keysLoaded {
		signed, ok, err := a.KeySets.Load(ctx)
		if err != nil {
			return fmt.Errorf("applier: key set store unreadable: %w", err)
		}
		if ok && signed != "" {
			_ = a.Verifier.UpdateKeys(signed)
			a.keysStored = signed
		}
		a.keysLoaded = true
	}
	if src, ok := a.Roid.(KeySetSource); ok {
		if signed, err := src.KeySet(ctx, "policy-bundle"); err == nil && signed != "" {
			_ = a.Verifier.UpdateKeys(signed)
		}
	}
	if cur := a.Verifier.KeySet(); cur != "" && cur != a.keysStored {
		if err := a.KeySets.Store(ctx, cur); err == nil {
			a.keysStored = cur
		}
	}
	return nil
}

// prepareCanary picks the canary for the next pass: at the first pass the
// one already on the live list, if any, so a restart does not turn it
// over.
func (a *Applier) prepareCanary(ctx context.Context) {
	if a.Probe == nil {
		return
	}
	if a.canaryWant == "" {
		a.canaryWant = compile.DenyCanaries[0]
		if cm, ok, err := a.Kube.Get(ctx, kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName); err == nil && ok &&
			cm.Data[compile.DenyCanaries[1]] != "" && cm.Data[compile.DenyCanaries[0]] == "" {
			a.canaryWant = compile.DenyCanaries[1]
		}
		a.canaryTurned = a.Now()
	}
	a.rec.Canary = a.canaryWant
}

// checkCanary asks the API server, in two dry runs, whether the canary on
// the live list is refused and the other one is not. It reports whether
// the canary state changed.
func (a *Applier) checkCanary(ctx context.Context) bool {
	if a.Probe == nil {
		return false
	}
	before, beforeReason := a.canaryState, a.canaryReason
	reason := a.canaryProbe(ctx)
	now := a.Now()
	if reason == "" {
		a.canaryFail, a.canaryState, a.canaryReason = time.Time{}, CanaryOK, ""
		every := a.CanaryEvery
		if every <= 0 {
			every = 30 * time.Second
		}
		if now.Sub(a.canaryTurned) >= every {
			a.canaryWant = other(a.canaryWant)
			a.canaryTurned = now
		}
	} else {
		grace := a.CanaryGrace
		if grace <= 0 {
			grace = 10 * time.Second
		}
		if a.canaryFail.IsZero() {
			a.canaryFail = now
		}
		if now.Sub(a.canaryFail) >= grace {
			a.canaryState, a.canaryReason = CanaryFailing, reason
		}
	}
	return a.canaryState != before || a.canaryReason != beforeReason
}

func other(c string) string {
	if c == compile.DenyCanaries[0] {
		return compile.DenyCanaries[1]
	}
	return compile.DenyCanaries[0]
}

// canaryProbe returns why the deny list does not cut, or "" when it does.
func (a *Applier) canaryProbe(ctx context.Context) string {
	cm, ok, err := a.Kube.Get(ctx, kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	switch {
	case err != nil:
		return "cannot read the deny list: " + err.Error()
	case !ok:
		return "the deny list is missing"
	}
	var listed []string
	for _, c := range compile.DenyCanaries {
		if cm.Data[c] != "" {
			listed = append(listed, c)
		}
	}
	if len(listed) != 1 {
		return fmt.Sprintf("the deny list holds %d canaries, want 1", len(listed))
	}
	on, off := listed[0], other(listed[0])
	ron, mon, err := a.Probe.DenyProbe(ctx, compile.CanaryUser(on), a.CanaryNamespace)
	if err != nil {
		return "probe as the listed canary: " + err.Error()
	}
	roff, moff, err := a.Probe.DenyProbe(ctx, compile.CanaryUser(off), a.CanaryNamespace)
	if err != nil {
		return "probe as the unlisted canary: " + err.Error()
	}
	switch {
	case roff == kubeapi.ProbeDenied:
		return "the API server refused the canary that is not on the list: the deny policy does not see changes to its list (was it re-created? restart kube-apiserver)"
	case ron == kubeapi.ProbeAllowed:
		return "the API server let the listed canary write: the deny list does not cut (deny policy or binding missing or changed)"
	case ron != kubeapi.ProbeDenied:
		return "the listed canary was refused, but not by the deny policy: " + mon
	case roff != kubeapi.ProbeAllowed:
		return "the unlisted canary was refused, but not by the deny policy: " + moff
	}
	return ""
}

// report sends a status that differs from the last one sent, or any status
// once the heartbeat interval has passed. A failed send is tried again at
// the next pass.
func (a *Applier) report(ctx context.Context, st Status) {
	st.PassMS = time.Since(a.passFrom).Milliseconds()
	every := a.ReportEvery
	if every <= 0 {
		every = 5 * time.Minute
	}
	same := a.hasSent && !newEvents(st) && st.Version == a.sent.Version && st.Digest == a.sent.Digest &&
		st.Applied == a.sent.Applied && st.Error == a.sent.Error && st.DenyOnly == a.sent.DenyOnly &&
		st.Canary == a.sent.Canary && st.CanaryReason == a.sent.CanaryReason &&
		(a.relay == nil || relayInfoSame(a.info, a.sentInfo))
	if same && a.Now().Sub(a.sentAt) < every {
		return
	}
	if a.relay != nil {
		a.relay.SetInfo(a.info)
	}
	if err := a.Roid.Report(ctx, st); err != nil {
		return
	}
	a.sent, a.sentAt, a.hasSent, a.sentInfo = st, a.Now(), true, a.info
}

// relayInfoSame compares the relay fields that make a status worth a write
// of its own: the namespaces, the lagging and fresh flags and the
// last verified envelope. The age and the sequence are not among them.
func relayInfoSame(x, y RelayInfo) bool {
	return x.NeedsFresh == y.NeedsFresh && x.FreshNonce == y.FreshNonce && x.Lagging == y.Lagging &&
		x.VerifyError == y.VerifyError && x.SeenEnvelopeSHA256 == y.SeenEnvelopeSHA256 && slices.Equal(x.Namespaces, y.Namespaces)
}

// newEvents reports whether a status carries an event worth a report of
// its own. The deny-only marker is not one: every pass of a deny-only
// bundle emits it, and DenyOnly in the status already says so.
func newEvents(st Status) bool {
	for typ, n := range st.Events {
		if n > 0 && !(st.DenyOnly && typ == reconcile.EvDenyOnly) {
			return true
		}
	}
	return false
}

func counts(rep reconcile.Report) map[string]int {
	if len(rep.Events) == 0 {
		return nil
	}
	m := map[string]int{}
	for _, e := range rep.Events {
		m[e.Type]++
	}
	return m
}

// Run runs a pass at start and then every interval until ctx ends. A
// failed pass is logged by the caller through onPass and retried at the
// next tick.
func (a *Applier) Run(ctx context.Context, every time.Duration, onPass func(Result, error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		res, err := a.RunOnce(ctx)
		if onPass != nil {
			onPass(res, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
