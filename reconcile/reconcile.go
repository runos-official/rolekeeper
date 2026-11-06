// Package reconcile applies a compiled projection to a cluster and repairs
// drift. A hand edit of a RunOS-owned object is put back and reported as
// audit event projection.drift.
package reconcile

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

// Kube is the cluster side the reconciler needs.
type Kube interface {
	// Get returns a live object, or ok=false when it does not exist.
	Get(ctx context.Context, kind, ns, name string) (o kobj.Object, ok bool, err error)
	// Create creates the object. Replace overwrites it whole (Namespace:
	// merges the labels only).
	Create(ctx context.Context, o kobj.Object) error
	Replace(ctx context.Context, o kobj.Object) error
	Delete(ctx context.Context, kind, ns, name string) error
	// ListManaged lists objects of one kind that carry runos.com/roid-managed=true,
	// in every namespace.
	ListManaged(ctx context.Context, kind string) ([]kobj.Object, error)
	// ListRoleBindings lists every RoleBinding in one namespace.
	ListRoleBindings(ctx context.Context, ns string) ([]kobj.Object, error)
}

// Event is one audit record.
type Event struct {
	Type          string    `json:"type"`
	At            time.Time `json:"at"`
	Object        string    `json:"object"`
	Fields        []string  `json:"fields,omitempty"`
	PolicyVersion string    `json:"policy_version"`
	Action        string    `json:"action"`
}

// Event types.
const (
	EvDrift   = "projection.drift"           // a RunOS-owned object was edited or deleted by hand
	EvForeign = "projection.foreign_binding" // a hand-made binding names a runos: subject
	EvApplied = "projection.applied"         // a new object from a policy change
	EvRemoved = "projection.removed"         // an object the policy no longer holds
	EvRefused = "projection.refused"         // the compiled set failed Lint; nothing applied
	// EvBreakGlassExpired: a Role or RoleBinding written under break-glass
	// was removed because its stamp expired.
	EvBreakGlassExpired = "projection.breakglass_expired"
	// EvDenyOnly: the compiler refused the projection, and only the deny
	// list was applied.
	EvDenyOnly = "projection.deny_only"
	// EvDenyListMissing: the deny list ConfigMap was gone and was written
	// back. A missing list allows every write, so this always
	// alerts.
	EvDenyListMissing = "projection.deny_list_missing"
	// EvDenyPolicyMissing: the deny policy or its binding is gone, and the
	// reconciler did not create it (KeepDenyPolicy). The installer
	// owns it; see the Kubernetes access runbook.
	EvDenyPolicyMissing = "projection.deny_policy_missing"
)

// Sink receives audit events.
type Sink interface{ Add(Event) }

// Report is the result of one pass.
type Report struct {
	Events []Event
}

// Count returns the number of events of one type.
func (r Report) Count(typ string) int {
	n := 0
	for _, e := range r.Events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

// Reconciler remembers what it applied, so a missing object it applied
// before counts as drift (a hand delete), not as a new object.
type Reconciler struct {
	Kube  Kube
	Sink  Sink
	Now   func() time.Time
	known map[string]bool
	// stamped remembers when a break-glass object was first seen.
	stamped map[string]time.Time
	// Canary is the deny canary key the applier keeps on the list
	// (compile.DenyCanaries). It is written with the list, and a
	// difference in canary keys alone is applied without a drift event.
	Canary string
	// KeepDenyPolicy says the installer owns the deny policy and its
	// binding: a missing one is reported (EvDenyPolicyMissing) and never
	// created, because a re-created policy goes blind to its list until
	// kube-apiserver restarts. The in-cluster applier sets it.
	KeepDenyPolicy bool
	// policyGone remembers a missing deny policy or binding already
	// reported, so a gap is reported once, not every pass.
	policyGone map[string]bool
}

// ErrLint means the compiled set broke an escalation rule.
var ErrLint = errors.New("reconcile: compiled set fails lint; nothing applied")

func (r *Reconciler) emit(rep *Report, typ, obj, pv, action string, fields ...string) {
	e := Event{Type: typ, At: r.Now(), Object: obj, Fields: fields, PolicyVersion: pv, Action: action}
	rep.Events = append(rep.Events, e)
	if r.Sink != nil {
		r.Sink.Add(e)
	}
}

// managedKinds are the kinds a pass lists to remove what the policy no
// longer holds. The binding goes before the policy and its list.
var managedKinds = []string{kobj.KindClusterRole, kobj.KindClusterRoleBinding, kobj.KindRoleBinding,
	kobj.KindVAPBinding, kobj.KindVAP, kobj.KindConfigMap}

// Pass applies one compiled projection: it lints first, then creates,
// repairs or deletes, and reports every change. Lint runs before any write
// (standing rule: checks go in front of the destructive step).
//
// An Output with DenyOnly set holds only the deny-list objects, because the
// compiler refused the rest. Pass hands it to PassDenyOnly and still returns
// ErrRefused, so it never removes the person bindings that the missing
// objects would imply.
func (r *Reconciler) Pass(ctx context.Context, out compile.Output, managedNS []string) (Report, error) {
	if out.DenyOnly {
		rep, err := r.PassDenyOnly(ctx, out)
		if err != nil {
			return rep, err
		}
		return rep, ErrRefused
	}
	var rep Report
	pv := out.PolicyVersion
	if r.known == nil {
		r.known = map[string]bool{}
	}
	if v := append(compile.Lint(out.Objects), compile.LintScope(out.Objects, managedNS)...); len(v) > 0 {
		r.emit(&rep, EvRefused, "projection", pv, "none", v...)
		// A finding anywhere in the bundle never stops the deny list: the
		// deny objects are linted alone, and if they are clean they land
		// (list, policy, binding). Nothing else is written or removed. A
		// deny list that fails its own lint writes nothing.
		deny := DenyObjects(out.Objects)
		if len(compile.Lint(deny)) == 0 {
			if err := r.apply(ctx, &rep, r.withCanary(deny), pv, nil); err != nil {
				return rep, err
			}
		}
		return rep, ErrLint
	}
	// The deny list goes before everything else: it changes
	// rarely, it is small, and it is the one revocation that must not queue
	// behind a Get for every other object. The list goes first, then the
	// policy, then the binding.
	objs := r.withCanary(denyFirst(out.Objects))
	if err := r.apply(ctx, &rep, objs[:countDeny(objs)], pv, nil); err != nil {
		return rep, err
	}
	// The lists below are also the pass's view of the cluster: an
	// object a list returned needs no Get of its own, so a pass is a few
	// lists and one write per changed object.
	seen := map[string]kobj.Object{}
	// Removals and foreign bindings go next: a revocation must not wait
	// behind the creates and repairs of the same pass.
	desired := map[string]bool{}
	for _, o := range out.Objects {
		desired[o.Key()] = true
	}
	for _, kind := range managedKinds {
		live, err := r.Kube.ListManaged(ctx, kind)
		if err != nil {
			return rep, err
		}
		for _, o := range live {
			if desired[o.Key()] {
				seen[o.Key()] = o
				continue
			}
			if compile.IsKeptDenyObject(o.Kind, o.Name) {
				continue // never deleted, not even when a bundle leaves it out
			}
			if isDenyList(o) {
				// A missing list allows every write, so a bundle that
				// leaves the list out keeps the live one. roid
				// always sends the list; an empty list is how it clears.
				continue
			}
			if err := r.Kube.Delete(ctx, o.Kind, o.Namespace, o.Name); err != nil {
				return rep, err
			}
			delete(r.known, o.Key())
			r.emit(&rep, EvRemoved, o.Key(), pv, "deleted", "was "+o.Labels[kobj.LabelPolicyVersion])
		}
	}
	for _, ns := range managedNS {
		rbs, err := r.Kube.ListRoleBindings(ctx, ns)
		if err != nil {
			return rep, err
		}
		for _, o := range rbs {
			if desired[o.Key()] {
				seen[o.Key()] = o
				continue
			}
			if o.Labels[kobj.LabelManaged] == "true" {
				continue
			}
			typ, names := r.foreign(o)
			if typ == "" {
				continue
			}
			if err := r.Kube.Delete(ctx, o.Kind, o.Namespace, o.Name); err != nil {
				return rep, err
			}
			delete(r.stamped, o.Key())
			r.emit(&rep, typ, o.Key(), pv, "deleted", names...)
		}
	}
	return rep, r.apply(ctx, &rep, objs[countDeny(objs):], pv, seen)
}

// ErrRefused means the compiler refused the projection. Only the deny list
// was applied.
var ErrRefused = errors.New("reconcile: compiler refused the projection; only the deny list was applied")

// PassDenyOnly applies the deny-list objects of a refused projection and
// nothing else: no removal and no sweep.
func (r *Reconciler) PassDenyOnly(ctx context.Context, out compile.Output) (Report, error) {
	var rep Report
	if r.known == nil {
		r.known = map[string]bool{}
	}
	objs := r.withCanary(denyFirst(out.Objects))
	n := countDeny(objs)
	if err := r.apply(ctx, &rep, objs[:n], out.PolicyVersion, nil); err != nil {
		return rep, err
	}
	r.emit(&rep, EvDenyOnly, "projection", out.PolicyVersion, "deny list applied", "the projection was refused; no other object changed")
	return rep, nil
}

// DenyObjects returns the deny-list objects of a bundle (the list, the
// policy and the binding), in the order list, policy, binding. The deny
// list never depends on the other objects of the bundle.
func DenyObjects(objs []kobj.Object) []kobj.Object {
	var d []kobj.Object
	for _, o := range objs {
		if isDeny(o) {
			d = append(d, o)
		}
	}
	return denyFirst(d)
}

// PassDenyListOnly applies the deny objects of out after they pass lint on
// their own, and nothing else: no removal and no sweep. The applier runs it
// for a bundle that names other namespaces than the cluster labels (the
// bundle lags, 5.4). Deny objects that fail lint write nothing (ErrLint).
func (r *Reconciler) PassDenyListOnly(ctx context.Context, out compile.Output) (Report, error) {
	deny := DenyObjects(out.Objects)
	if v := compile.Lint(deny); len(v) > 0 {
		var rep Report
		r.emit(&rep, EvRefused, "projection", out.PolicyVersion, "none", v...)
		return rep, ErrLint
	}
	return r.PassDenyOnly(ctx, compile.Output{PolicyVersion: out.PolicyVersion, Objects: deny, DenyOnly: true})
}

// RepairDenyList writes the deny list back when it is missing and does
// nothing else. The applier runs it when roid cannot be reached, with the
// last bundle it applied: a missing list allows every write, and an older
// list is better than none. A list that exists is left alone.
func (r *Reconciler) RepairDenyList(ctx context.Context, objs []kobj.Object) (Report, error) {
	var rep Report
	for _, o := range r.withCanary(denyFirst(objs)) {
		if !isDenyList(o) {
			continue
		}
		_, ok, err := r.Kube.Get(ctx, o.Kind, o.Namespace, o.Name)
		if err != nil || ok {
			return rep, err
		}
		if err := r.Kube.Create(ctx, o); err != nil {
			return rep, err
		}
		r.emit(&rep, EvDenyListMissing, o.Key(), o.Labels[kobj.LabelPolicyVersion], "recreated", "from the last applied bundle; roid unreachable")
	}
	return rep, nil
}

func isDenyList(o kobj.Object) bool {
	return o.Kind == kobj.KindConfigMap && o.Name == compile.DenyPolicyName && o.Namespace == compile.DenyNamespace
}

// withCanary returns objs with the canary key added to a copy of the deny
// list.
func (r *Reconciler) withCanary(objs []kobj.Object) []kobj.Object {
	if r.Canary == "" {
		return objs
	}
	out := slices.Clone(objs)
	for i, o := range out {
		if isDenyList(o) {
			o = o.Clone()
			if o.Data == nil {
				o.Data = map[string]string{}
			}
			o.Data[r.Canary] = compile.CanaryUntil
			out[i] = o
		}
	}
	return out
}

// onlyCanary reports whether two deny lists differ in canary keys only.
func onlyCanary(desired, live kobj.Object) bool {
	strip := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range m {
			if !compile.IsDenyCanary(k) {
				out[k] = v
			}
		}
		return out
	}
	return maps.Equal(strip(desired.Data), strip(live.Data))
}

func isDeny(o kobj.Object) bool {
	switch o.Kind {
	case kobj.KindConfigMap:
		return o.Name == compile.DenyPolicyName && o.Namespace == compile.DenyNamespace
	case kobj.KindVAP, kobj.KindVAPBinding:
		return o.Name == compile.DenyPolicyName
	}
	return false
}

// denyFirst returns the objects with the deny-list objects first, in the
// order list, policy, binding, and the rest in their given order.
func denyFirst(objs []kobj.Object) []kobj.Object {
	rank := map[string]int{kobj.KindConfigMap: 0, kobj.KindVAP: 1, kobj.KindVAPBinding: 2}
	var d, rest []kobj.Object
	for _, o := range objs {
		if isDeny(o) {
			d = append(d, o)
		} else {
			rest = append(rest, o)
		}
	}
	slices.SortStableFunc(d, func(a, b kobj.Object) int { return rank[a.Kind] - rank[b.Kind] })
	return append(d, rest...)
}

func countDeny(objs []kobj.Object) int {
	n := 0
	for n < len(objs) && isDeny(objs[n]) {
		n++
	}
	return n
}

// foreign says whether a RoleBinding that is neither desired nor managed is
// to be removed, with the audit event type and the subject names.
//
//   - A stamped binding (break-glass) stands until its stamp
//     expires, or until BreakGlassStampMax after it was first seen, then goes.
//     A stamp that is not an RFC 3339 time expires at once.
//   - A binding that names a runos: subject is a second permission set (R6).
//   - A binding of a fixed RunOS role to a User or Group is one too, whatever
//     the subject is called. Workload ServiceAccount bindings
//     stay.
func (r *Reconciler) foreign(o kobj.Object) (typ string, names []string) {
	now := r.Now()
	if stamp, ok := o.Annotations[compile.BreakGlassStamp]; ok {
		if r.stamped == nil {
			r.stamped = map[string]time.Time{}
		}
		first, seen := r.stamped[o.Key()]
		if !seen {
			first = now
			r.stamped[o.Key()] = first
		}
		exp, err := time.Parse(time.RFC3339, stamp)
		if err != nil || !now.Before(exp) || !now.Before(first.Add(compile.BreakGlassStampMax)) {
			return EvBreakGlassExpired, []string{"stamp " + stamp}
		}
		return "", nil
	}
	for _, s := range o.Subjects {
		if strings.HasPrefix(s.Name, "runos:") {
			names = append(names, s.Kind+" "+s.Name)
		}
	}
	if len(names) > 0 {
		return EvForeign, names
	}
	if o.RoleRef != nil && (compile.IsFixedRole(o.RoleRef.Name)) {
		for _, s := range o.Subjects {
			if s.Kind == "User" || s.Kind == "Group" {
				names = append(names, s.Kind+" "+s.Name)
			}
		}
		if len(names) > 0 {
			return EvForeign, names
		}
	}
	return "", nil
}

// apply creates, repairs or updates each object and reports it. listed
// holds live objects this pass already read with a list; any other object
// is read with a Get (a new object, a namespace, or one whose managed label
// was removed by hand).
func (r *Reconciler) apply(ctx context.Context, rep *Report, objs []kobj.Object, pv string, listed map[string]kobj.Object) error {
	for _, o := range objs {
		live, ok := listed[o.Key()]
		if !ok {
			var err error
			if live, ok, err = r.Kube.Get(ctx, o.Kind, o.Namespace, o.Name); err != nil {
				return err
			}
		}
		if ok {
			delete(r.policyGone, o.Key())
		}
		switch {
		case !ok && o.Kind == kobj.KindNamespace:
			// RunOS manages labels on namespaces that exist; creating the
			// namespace is the app deployment path, not this projection.
			continue
		case !ok && r.KeepDenyPolicy && compile.IsKeptDenyObject(o.Kind, o.Name):
			if r.policyGone == nil {
				r.policyGone = map[string]bool{}
			}
			if !r.policyGone[o.Key()] {
				r.policyGone[o.Key()] = true
				r.emit(rep, EvDenyPolicyMissing, o.Key(), pv, "not created", "the installer owns it; a re-created policy is blind to its list")
			}
			continue
		case !ok:
			if isDenyList(o) {
				r.emit(rep, EvDenyListMissing, o.Key(), pv, "recreated")
			}
			if err := r.Kube.Create(ctx, o); err != nil {
				return err
			}
			if r.known[o.Key()] {
				r.emit(rep, EvDrift, o.Key(), pv, "repaired", "deleted")
			} else {
				r.emit(rep, EvApplied, o.Key(), pv, "created")
			}
		default:
			d := kobj.Diff(o, live)
			if len(d) == 0 {
				break
			}
			if isDenyList(o) && slices.Equal(d, []string{"data"}) && onlyCanary(o, live) {
				// The canary turned over: no drift, no event.
				if err := r.Kube.Replace(ctx, o); err != nil {
					return err
				}
				break
			}
			if slices.Contains(d, "roleRef") {
				// roleRef is immutable: delete, then create.
				if err := r.Kube.Delete(ctx, o.Kind, o.Namespace, o.Name); err != nil {
					return err
				}
				if err := r.Kube.Create(ctx, o); err != nil {
					return err
				}
			} else if err := r.Kube.Replace(ctx, o); err != nil {
				return err
			}
			if o.Kind == kobj.KindNamespace && live.Labels[kobj.LabelAccess] != "true" {
				r.emit(rep, EvApplied, o.Key(), pv, "adopted", d...)
			} else if onlyVersion(d) {
				r.emit(rep, EvApplied, o.Key(), pv, "updated", d...)
			} else {
				r.emit(rep, EvDrift, o.Key(), pv, "repaired", d...)
			}
		}
		r.known[o.Key()] = true
	}
	return nil
}

// onlyVersion reports whether the only difference is the policy-version
// label, which is a normal policy change rather than a hand edit.
func onlyVersion(d []string) bool {
	return len(d) == 1 && strings.HasPrefix(d[0], "label "+kobj.LabelPolicyVersion+"=")
}
