// Package keys holds the per-purpose key sets: publish-before-use
// rotation, retirement after the overlap window, removal of a compromised key
// through a reset signed by the offline root, and restore replay.
//
// Manager is the issuer side (inside the identity service; it holds Signer
// handles only). View is the verifier side (API, cluster, VPN server, gate):
// it pins the root public key and the install-time key set, then accepts
// only root-signed full key sets.
//
// Every published key set is a
// full set signed by the offline root, and holds the active key and one
// standby. Routine rotation promotes the standby, which verifiers already
// hold, so it needs no new signature. The next root ceremony (Publish)
// adds a new standby. A leaf key never signs a key set that a View accepts.
package keys

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
	"github.com/runos-official/rolekeeper/internal/signer/revlog"
	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
)

// DocType is the typ header of a key-set document.
const DocType = roottrust.TypKeySet

var (
	ErrRotationForbidden = errors.New("keys: rotation_forbidden")
	ErrNextExists        = errors.New("keys: next key already published")
	ErrNoNext            = errors.New("keys: no next key published")
	ErrPublishLeadNotMet = errors.New("keys: next key not published long enough")
	ErrNoActive          = errors.New("keys: no active key")
	ErrRollback          = errors.New("keys: keyset_rollback")
	ErrRootRequired      = errors.New("keys: a new epoch needs the root signature")
	ErrKeyRemoved        = errors.New("keys: key_removed")
	ErrUnknownKey        = errors.New("keys: unknown_key")
	ErrWrongType         = errors.New("keys: wrong_type")
	ErrNoChange          = errors.New("keys: no change")
	ErrUnknownPurpose    = errors.New("keys: purpose not bootstrapped")
	// ErrNotRootPublished: the standby exists in custody but no root
	// ceremony has published it, so verifiers do not hold it yet.
	ErrNotRootPublished = errors.New("keys: standby not root-published")
	// ErrRootRank: the set is signed by an earlier root of the chain than
	// the set the view holds: a view never goes back to an older root.
	ErrRootRank = roottrust.ErrRootRank
	// ErrBadKeySet: a root-signed set lacks the active key or the standby.
	ErrBadKeySet = errors.New("keys: key set must hold one active and one standby key")
	// ErrState: the durable view state is unreadable or not root-signed.
	ErrState = errors.New("keys: view state unreadable")
	// ErrKeyChanged: a document carries another public key or algorithm
	// under a key id that is already known.
	ErrKeyChanged = errors.New("keys: known key id carries a different public key")
	// ErrFloorLowered: a document lowers a per-subject floor.
	ErrFloorLowered = errors.New("keys: floor lowered")
	// ErrCustodyMismatch: a key-set entry names a key whose public half is
	// not the one custody holds.
	ErrCustodyMismatch = errors.New("keys: key set does not match custody")
)

// CheckSuccessor holds next to the rules every newer document keeps
// against an older one of the same purpose: a key id
// that both hold keeps its public key and algorithm, a removed key stays
// removed, and no floor goes down. The floor rule is for the documents
// roid's Manager keeps (its live floors only grow) and for the ceremony
// log. A View does not use it for floors: the root-signed set
// holds no floor table, and a View keeps its floors locally, only up.
func CheckSuccessor(prev, next Doc) error {
	if err := checkSuccessorKeys(prev, next); err != nil {
		return err
	}
	for subject, floor := range prev.MinVersions {
		if next.MinVersions[subject] < floor {
			return fmt.Errorf("%w: %s from %d to %d", ErrFloorLowered, subject, floor, next.MinVersions[subject])
		}
	}
	return nil
}

// checkSuccessorKeys is the key half of CheckSuccessor: public keys do not
// change under a known id, and a removed key stays removed.
func checkSuccessorKeys(prev, next Doc) error {
	for _, k := range next.Keys {
		if p := prev.Find(k.Kid); p != nil && (!bytes.Equal(p.PublicDER, k.PublicDER) || p.Alg != k.Alg) {
			return fmt.Errorf("%w: %s", ErrKeyChanged, k.Kid)
		}
	}
	removed := map[string]bool{}
	for _, r := range next.Removed {
		removed[r] = true
	}
	for _, r := range prev.Removed {
		if !removed[r] {
			return fmt.Errorf("%w: %s left the removed list", ErrKeyRemoved, r)
		}
	}
	return nil
}

type State string

const (
	StateNext     State = "next"     // standby: published (PublishedAt set) or pending a root ceremony (PublishedAt zero)
	StateActive   State = "active"   // signing
	StateRetiring State = "retiring" // published, no longer signing
)

type PublishedKey struct {
	Kid         string           `json:"kid"`
	Alg         signer.Algorithm `json:"alg"`
	State       State            `json:"state"`
	PublicDER   []byte           `json:"x"`
	PublishedAt time.Time        `json:"published_at"`
	ActivatedAt time.Time        `json:"activated_at,omitzero"`
	RetiringAt  time.Time        `json:"retiring_at,omitzero"`
}

// Doc is one purpose's key set. (Epoch, Version) orders documents. Only the
// root raises Epoch; a root document is a full replacement.
type Doc struct {
	Purpose  signer.Purpose `json:"purpose"`
	Epoch    uint64         `json:"epoch"`
	Version  uint64         `json:"version"`
	IssuedAt time.Time      `json:"issued_at"`
	Keys     []PublishedKey `json:"keys"`
	Removed  []string       `json:"removed,omitempty"`
	// MinVersions pins, per subject, the lowest version of a document that
	// this purpose's keys sign and a verifier may still accept.
	// For the emergency roster the subject is the account and the document
	// is its roster list.
	//
	// The table lives in the online Manager (roid's live floors)
	// and in the install pin of one account. A root-signed set carries none
	// (SignedForm): it is served to anyone, so a table in it would name
	// every account that has emergency keys. A verifier keeps its floor
	// locally, from its pin and from the version of every list it installs.
	// An older root-signed set may still hold a table; a View takes the
	// higher floor of each subject and never lowers one.
	MinVersions map[string]uint64 `json:"min_versions,omitempty"`
}

func (d Doc) clone() Doc {
	c := d
	c.Keys = append([]PublishedKey(nil), d.Keys...)
	c.Removed = append([]string(nil), d.Removed...)
	if d.MinVersions != nil {
		c.MinVersions = make(map[string]uint64, len(d.MinVersions))
		for k, v := range d.MinVersions {
			c.MinVersions[k] = v
		}
	}
	return c
}

// MinVersion is the pinned floor for subject (0 when none).
func (d Doc) MinVersion(subject string) uint64 { return d.MinVersions[subject] }

// SignedForm is the document as the offline root signs it: the same keys
// and the same order, without the floor table. Every published
// set and every compromise reset is signed in this form.
func (d Doc) SignedForm() Doc {
	c := d.clone()
	c.MinVersions = nil
	return c
}

// FloorsOnlyFor returns a copy of the document that carries the floor of
// subject and no other. A subject with no floor leaves the map empty. It is
// for an anonymous install pin, which must not name accounts the asker did
// not name. The copy is no root-signed set: a verifier installs
// it as a pin only, and every root-signed set still holds all floors.
func (d Doc) FloorsOnlyFor(subject string) Doc {
	c := d.clone()
	c.MinVersions = nil
	if f := d.MinVersions[subject]; f > 0 {
		c.MinVersions = map[string]uint64{subject: f}
	}
	return c
}

func (d Doc) Find(kid string) *PublishedKey {
	for i := range d.Keys {
		if d.Keys[i].Kid == kid {
			return &d.Keys[i]
		}
	}
	return nil
}

func (d Doc) inState(s State) *PublishedKey {
	for i := range d.Keys {
		if d.Keys[i].State == s {
			return &d.Keys[i]
		}
	}
	return nil
}

// Active returns the active key, or nil.
func (d Doc) Active() *PublishedKey { return d.inState(StateActive) }

// ---------------------------------------------------------------- Manager

type Manager struct {
	mu          sync.Mutex
	backend     signer.Backend
	log         revlog.Appender
	now         func() time.Time
	docs        map[signer.Purpose]Doc
	watermark   uint64
	needsReplay bool
	anchor      revlog.Anchor
	pending     map[signer.Purpose]*Request // offline-root requests waiting for a signature
	// lastSigned is the last root-signed set per purpose (compact JWS). It
	// is the evidence a Retirer backend checks before it disables a
	// retired key.
	lastSigned map[signer.Purpose]string
}

func NewManager(b signer.Backend, log revlog.Appender, now func() time.Time) *Manager {
	return &Manager{backend: b, log: log, now: now, docs: map[signer.Purpose]Doc{}, pending: map[signer.Purpose]*Request{},
		lastSigned: map[signer.Purpose]string{}}
}

type Snapshot struct {
	Docs      map[signer.Purpose]Doc `json:"docs"`
	Watermark uint64                 `json:"watermark"`
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{Docs: map[signer.Purpose]Doc{}, Watermark: m.watermark}
	for p, d := range m.docs {
		s.Docs[p] = d.clone()
	}
	return s
}

// RestoreManager loads a backup. It refuses to sign, publish or rotate until
// Replay has applied the external log.
func RestoreManager(b signer.Backend, log revlog.Appender, now func() time.Time, s Snapshot) *Manager {
	m := NewManager(b, log, now)
	for p, d := range s.Docs {
		m.docs[p] = d.clone()
	}
	m.watermark = s.Watermark
	m.needsReplay = true
	return m
}

type compromisePayload struct {
	Doc    Doc    `json:"doc"`
	Signed string `json:"signed"`
}

// SetAnchor adds an external log head that Replay must reach.
func (m *Manager) SetAnchor(a revlog.Anchor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.anchor = a
}

// Replay applies the log entries after the snapshot watermark. It checks
// the entries first (revlog.VerifyReplay). The log is not trusted
// for key truth: every entry must keep the successor rules
// against the document before it (CheckSuccessor: same public key under a
// known id, removed stays removed, floors only go up), every key the
// resulting sets name must be the key custody holds, and every compromise
// entry must disable its key in custody. On any failure Replay applies
// nothing and the manager stays sealed.
func (m *Manager) Replay(entries []revlog.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := revlog.VerifyReplay(entries, m.watermark, revlog.AnchorOf(m.log, m.anchor)...); err != nil {
		return err
	}
	docs := map[signer.Purpose]Doc{}
	for p, d := range m.docs {
		docs[p] = d.clone()
	}
	type retire struct{ kid, evidence string }
	var retires []retire
	signed := map[signer.Purpose]string{}
	watermark := m.watermark
	apply := func(d Doc, seq uint64) error {
		if prev, ok := docs[d.Purpose]; ok {
			if err := CheckSuccessor(prev, d); err != nil {
				return fmt.Errorf("keys: replay entry %d: %w", seq, err)
			}
			if d.Epoch < prev.Epoch || (d.Epoch == prev.Epoch && d.Version < prev.Version) {
				return fmt.Errorf("keys: replay entry %d: %w", seq, ErrRollback)
			}
		}
		docs[d.Purpose] = d
		return nil
	}
	for _, e := range entries {
		if e.Seq <= watermark {
			continue
		}
		switch e.Kind {
		case revlog.KindKeySetPublished:
			var d Doc
			if err := json.Unmarshal(e.Payload, &d); err != nil {
				return err
			}
			if err := apply(d, e.Seq); err != nil {
				return err
			}
		case revlog.KindKeyCompromised:
			var c compromisePayload
			if err := json.Unmarshal(e.Payload, &c); err != nil {
				return err
			}
			if err := apply(c.Doc, e.Seq); err != nil {
				return err
			}
			retires = append(retires, retire{kid: e.Subject, evidence: c.Signed})
			signed[c.Doc.Purpose] = c.Signed
		}
		watermark = e.Seq
	}
	ctx := context.Background()
	for p, d := range docs {
		for _, k := range d.Keys {
			held, err := m.backend.PublicKey(ctx, k.Kid)
			if err != nil {
				return fmt.Errorf("%w: %s key %s: %v", ErrCustodyMismatch, p, k.Kid, err)
			}
			if !bytes.Equal(held.PublicDER, k.PublicDER) || held.Purpose != p {
				return fmt.Errorf("%w: %s key %s", ErrCustodyMismatch, p, k.Kid)
			}
		}
	}
	for _, r := range retires {
		if err := signer.Retire(ctx, m.backend, r.kid, r.evidence); err != nil {
			return fmt.Errorf("keys: replay could not disable compromised key %s in custody: %w", r.kid, err)
		}
	}
	m.docs, m.watermark = docs, watermark
	for p, sg := range signed {
		m.lastSigned[p] = sg
	}
	m.needsReplay = false
	return nil
}

func (m *Manager) ready() error {
	if m.needsReplay {
		return revlog.ErrReplayRequired
	}
	return nil
}

// commit writes the new document to the external log first, then applies it.
func (m *Manager) commit(kind revlog.Kind, subject string, payload any, d Doc) error {
	e, err := m.log.Append(kind, subject, payload)
	if err != nil {
		return err
	}
	m.docs[d.Purpose] = d
	m.watermark = e.Seq
	return nil
}

// newKey creates a key in custody. published is true when the key goes to
// verifiers in the same step (install pin or root-signed reset). A routine
// standby stays unpublished (zero PublishedAt) until the next Publish.
func (m *Manager) newKey(ctx context.Context, p signer.Purpose, alg signer.Algorithm, st State, published bool) (PublishedKey, error) {
	info, err := m.backend.CreateKey(ctx, p, alg)
	if err != nil {
		return PublishedKey{}, err
	}
	now := m.now().UTC()
	k := PublishedKey{Kid: info.ID, Alg: info.Algorithm, State: st, PublicDER: info.PublicDER}
	if published {
		k.PublishedAt = now
	}
	if st == StateActive {
		k.ActivatedAt = now
	}
	return k, nil
}

// Bootstrap creates the install-time key set: one active key, plus a
// published standby when the purpose rotates. The returned Doc is what a
// cluster pins at install.
func (m *Manager) Bootstrap(ctx context.Context, p signer.Purpose, alg signer.Algorithm) (Doc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return Doc{}, err
	}
	if p == signer.PurposeKeySetRoot || !p.Valid() {
		return Doc{}, signer.ErrWrongPurpose
	}
	if _, ok := m.docs[p]; ok {
		return Doc{}, fmt.Errorf("keys: %s already bootstrapped", p)
	}
	d := Doc{Purpose: p, Epoch: 1, Version: 1, IssuedAt: m.now().UTC()}
	a, err := m.newKey(ctx, p, alg, StateActive, true)
	if err != nil {
		return Doc{}, err
	}
	d.Keys = append(d.Keys, a)
	if p.Rotates() {
		n, err := m.newKey(ctx, p, alg, StateNext, true)
		if err != nil {
			return Doc{}, err
		}
		d.Keys = append(d.Keys, n)
	}
	if err := m.commit(revlog.KindKeySetPublished, string(p), d, d); err != nil {
		return Doc{}, err
	}
	return d.clone(), nil
}

func (m *Manager) doc(p signer.Purpose) (Doc, error) {
	d, ok := m.docs[p]
	if !ok {
		return Doc{}, ErrUnknownPurpose
	}
	return d.clone(), nil
}

// Doc returns a copy of the current key set for p.
func (m *Manager) Doc(p signer.Purpose) Doc {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, _ := m.doc(p)
	return d
}

// SetMinVersion raises the pinned floor for subject in p's key set. The
// change goes to the external log first, so a restore replays it. It
// reaches verifiers in the next install pin (Doc) and in the next
// root-signed set (Publish or Compromise); it needs no root signature on
// its own, because a floor only ever refuses more.
func (m *Manager) SetMinVersion(p signer.Purpose, subject string, v uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return err
	}
	if subject == "" {
		return errors.New("keys: empty floor subject")
	}
	d, err := m.doc(p)
	if err != nil {
		return err
	}
	if d.MinVersions[subject] >= v {
		return nil
	}
	if d.MinVersions == nil {
		d.MinVersions = map[string]uint64{}
	}
	d.MinVersions[subject] = v
	// A change of the set is a new version, like every other Manager step,
	// so the signer-held log can order it.
	d.Version++
	d.IssuedAt = m.now().UTC()
	return m.commit(revlog.KindKeySetPublished, string(p), d, d)
}

// BumpVersion moves the version of p's set up by one and changes nothing
// else. roid uses it before it exports a request for
// a version it exported before and never installed: that request may have
// been signed offline and the signed file lost, and the ceremony signs each
// version once. The new request is then for a version the ceremony has not
// seen. It needs no root signature, because what the root signs does not
// change. The change goes to the external log first, like every step.
func (m *Manager) BumpVersion(p signer.Purpose) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return err
	}
	d, err := m.doc(p)
	if err != nil {
		return err
	}
	d.Version++
	d.IssuedAt = m.now().UTC()
	return m.commit(revlog.KindKeySetPublished, string(p), d, d)
}

// PublishNext creates the next standby key. It does not sign with it, and
// verifiers do not hold it until the next root ceremony (Publish).
func (m *Manager) PublishNext(ctx context.Context, p signer.Purpose, alg signer.Algorithm) (signer.KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return signer.KeyInfo{}, err
	}
	return m.publishNext(ctx, p, alg)
}

func (m *Manager) publishNext(ctx context.Context, p signer.Purpose, alg signer.Algorithm) (signer.KeyInfo, error) {
	if !p.Rotates() {
		return signer.KeyInfo{}, ErrRotationForbidden
	}
	d, err := m.doc(p)
	if err != nil {
		return signer.KeyInfo{}, err
	}
	if d.inState(StateNext) != nil {
		return signer.KeyInfo{}, ErrNextExists
	}
	n, err := m.newKey(ctx, p, alg, StateNext, false)
	if err != nil {
		return signer.KeyInfo{}, err
	}
	d.Keys = append(d.Keys, n)
	d.Version++
	d.IssuedAt = m.now().UTC()
	if err := m.commit(revlog.KindKeySetPublished, string(p), d, d); err != nil {
		return signer.KeyInfo{}, err
	}
	return m.backend.PublicKey(ctx, n.Kid)
}

// Activate promotes the standby once a root ceremony has published it for
// the overlap window, and moves the old active key to retiring. It needs no
// root signature: verifiers already hold the standby.
func (m *Manager) Activate(ctx context.Context, p signer.Purpose) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return err
	}
	return m.activate(p)
}

func (m *Manager) activate(p signer.Purpose) error {
	if !p.Rotates() {
		return ErrRotationForbidden
	}
	d, err := m.doc(p)
	if err != nil {
		return err
	}
	n := d.inState(StateNext)
	if n == nil {
		return ErrNoNext
	}
	now := m.now().UTC()
	if n.PublishedAt.IsZero() {
		return fmt.Errorf("%w: %s", ErrNotRootPublished, n.Kid)
	}
	if now.Sub(n.PublishedAt) < p.RotationOverlap() {
		return fmt.Errorf("%w: published %s ago, need %s", ErrPublishLeadNotMet, now.Sub(n.PublishedAt), p.RotationOverlap())
	}
	if a := d.Active(); a != nil {
		a.State = StateRetiring
		a.RetiringAt = now
	}
	n.State = StateActive
	n.ActivatedAt = now
	d.Version++
	d.IssuedAt = now
	return m.commit(revlog.KindKeySetPublished, string(p), d, d)
}

// Rotate activates the next key (when the lead is met) and publishes a new
// standby, so a published, unused key always exists.
func (m *Manager) Rotate(ctx context.Context, p signer.Purpose, alg signer.Algorithm) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return err
	}
	d, err := m.doc(p)
	if err != nil {
		return err
	}
	if d.inState(StateNext) == nil {
		_, err := m.publishNext(ctx, p, alg)
		return err
	}
	if err := m.activate(p); err != nil {
		return err
	}
	_, err = m.publishNext(ctx, p, alg)
	return err
}

// RetireExpired drops retiring keys whose last use is at least the overlap
// window ago, and disables them in custody. Custody disables first: a key
// that custody will not disable yet (no root-signed set shows it retiring
// long enough) stays in the set as retiring, so it is never dropped while
// it can still sign.
func (m *Manager) RetireExpired(ctx context.Context, p signer.Purpose) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return nil, err
	}
	d, err := m.doc(p)
	if err != nil {
		return nil, err
	}
	now := m.now().UTC()
	var gone []string
	var firstErr error
	kept := make([]PublishedKey, 0, len(d.Keys))
	for _, k := range d.Keys {
		if k.State == StateRetiring && now.Sub(k.RetiringAt) >= p.RotationOverlap() {
			if err := signer.Retire(ctx, m.backend, k.Kid, m.lastSigned[p]); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				kept = append(kept, k)
				continue
			}
			gone = append(gone, k.Kid)
			continue
		}
		kept = append(kept, k)
	}
	if len(gone) == 0 {
		return nil, firstErr
	}
	d.Keys = kept
	d.Version++
	d.IssuedAt = now
	if err := m.commit(revlog.KindKeySetPublished, string(p), d, d); err != nil {
		return nil, err
	}
	return gone, firstErr
}

// ActiveSigner returns the signing handle for p.
func (m *Manager) ActiveSigner(ctx context.Context, p signer.Purpose) (*signer.Signer, error) {
	m.mu.Lock()
	if err := m.ready(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	d, err := m.doc(p)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	a := d.Active()
	if a == nil {
		return nil, ErrNoActive
	}
	s, err := signer.New(ctx, m.backend, a.Kid, p)
	if err != nil {
		return nil, err
	}
	// A strict signer socket needs the decision id on every sign.
	if id := signer.DecisionFromContext(ctx); id != "" {
		s = s.WithDecision(id)
	}
	return s, nil
}

// LegacyLeafSignedDoc returns the key-set document signed by the active
// key of the same purpose, the earlier format. Every View refuses
// it with ErrRootRequired. It exists only so tests can prove that refusal;
// production code publishes key sets with Publish.
func (m *Manager) LegacyLeafSignedDoc(ctx context.Context, p signer.Purpose) (string, error) {
	s, err := m.ActiveSigner(ctx, p)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	d, err := m.doc(p)
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return jws.Sign(s, DocType, raw)
}

// Compromise removes kid with a full key-set reset signed by root. The
// standby key (or a fresh key) becomes active at once and a new standby is
// published in the same document. The log entry is written before any state
// changes.
func (m *Manager) Compromise(ctx context.Context, p signer.Purpose, kid string, root *signer.Signer) (string, error) {
	if root.Purpose() != signer.PurposeKeySetRoot {
		return "", signer.ErrWrongPurpose
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.prepCompromise(ctx, p, kid)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(d.SignedForm())
	if err != nil {
		return "", err
	}
	signed, err := jws.Sign(root, DocType, raw)
	if err != nil {
		return "", err
	}
	return m.commitCompromise(ctx, kid, d, signed)
}

// prepCompromise builds the root-signed reset document for removing kid.
// The caller holds m.mu. It creates keys in custody when the reset needs
// them; an unused key does no harm if the ceremony never completes.
func (m *Manager) prepCompromise(ctx context.Context, p signer.Purpose, kid string) (Doc, error) {
	if err := m.ready(); err != nil {
		return Doc{}, err
	}
	if !p.Rotates() {
		return Doc{}, fmt.Errorf("%w: %s has no replacement path", ErrRotationForbidden, p)
	}
	d, err := m.doc(p)
	if err != nil {
		return Doc{}, err
	}
	bad := d.Find(kid)
	if bad == nil {
		return Doc{}, ErrUnknownKey
	}
	wasActive := bad.State == StateActive
	now := m.now().UTC()
	kept := make([]PublishedKey, 0, len(d.Keys))
	for _, k := range d.Keys {
		if k.Kid != kid {
			kept = append(kept, k)
		}
	}
	d.Keys = kept
	if wasActive {
		if n := d.inState(StateNext); n != nil {
			n.State, n.ActivatedAt = StateActive, now
		} else {
			a, err := m.newKey(ctx, p, bad.Alg, StateActive, true)
			if err != nil {
				return Doc{}, err
			}
			d.Keys = append(d.Keys, a)
		}
	}
	if d.inState(StateNext) == nil {
		n, err := m.newKey(ctx, p, bad.Alg, StateNext, true)
		if err != nil {
			return Doc{}, err
		}
		d.Keys = append(d.Keys, n)
	}
	for i := range d.Keys { // the reset publishes every key it carries
		if d.Keys[i].PublishedAt.IsZero() {
			d.Keys[i].PublishedAt = now
		}
	}
	d.Removed = append(d.Removed, kid)
	d.Epoch++
	d.Version = 1
	d.IssuedAt = now
	return d, nil
}

// commitCompromise logs the signed reset, applies it and disables the key
// in custody. The caller holds m.mu.
func (m *Manager) commitCompromise(ctx context.Context, kid string, d Doc, signed string) (string, error) {
	if err := m.commit(revlog.KindKeyCompromised, kid, compromisePayload{Doc: d, Signed: signed}, d); err != nil {
		return "", err
	}
	m.lastSigned[d.Purpose] = signed
	// The signed reset is the evidence custody checks.
	if err := signer.Retire(ctx, m.backend, kid, signed); err != nil {
		return signed, fmt.Errorf("keys: reset logged, but custody did not disable %s: %w", kid, err)
	}
	return signed, nil
}

// Publish is the root ceremony. It signs the full current key
// set with the offline root. The set must hold the active key and one
// standby. Keys that no ceremony published yet get PublishedAt now, so the
// publish lead for the standby starts here. The log entry is written
// before the state changes.
func (m *Manager) Publish(ctx context.Context, p signer.Purpose, root *signer.Signer) (string, error) {
	if root == nil || root.Purpose() != signer.PurposeKeySetRoot {
		return "", fmt.Errorf("%w: a key-set ceremony needs the keyset-root key", signer.ErrWrongPurpose)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.prepPublish(p)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(d.SignedForm())
	if err != nil {
		return "", err
	}
	signed, err := jws.Sign(root, DocType, raw)
	if err != nil {
		return "", err
	}
	if err := m.commit(revlog.KindKeySetPublished, string(p), d, d); err != nil {
		return "", err
	}
	m.lastSigned[p] = signed
	return signed, nil
}

// LastSigned returns the last root-signed set the manager committed for p,
// or "" when it holds none since its start.
func (m *Manager) LastSigned(p signer.Purpose) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSigned[p]
}

// prepPublish builds the next full key set for p. The caller holds m.mu.
func (m *Manager) prepPublish(p signer.Purpose) (Doc, error) {
	if err := m.ready(); err != nil {
		return Doc{}, err
	}
	if !p.Rotates() {
		return Doc{}, ErrRotationForbidden
	}
	d, err := m.doc(p)
	if err != nil {
		return Doc{}, err
	}
	if d.Active() == nil {
		return Doc{}, ErrNoActive
	}
	if d.inState(StateNext) == nil {
		return Doc{}, ErrNoNext
	}
	now := m.now().UTC()
	for i := range d.Keys {
		if d.Keys[i].PublishedAt.IsZero() {
			d.Keys[i].PublishedAt = now
		}
	}
	d.Version++
	d.IssuedAt = now
	return d, nil
}

// ---------------------------------------------------------------- View

type viewKey struct {
	pub crypto.PublicKey
	alg signer.Algorithm
}

// View is a verifier's copy of one purpose's key set.
type View struct {
	mu        sync.RWMutex
	purpose   signer.Purpose
	roots     roottrust.Verifier // the roots that sign a key set (the root chain)
	doc       Doc
	raw       []byte
	keys      map[string]viewKey
	removed   map[string]bool
	statePath string
	signed    string
	warned    string         // the root RootHealth last logged a warning for
	held      roottrust.Held // the held set's root: precedence and the use-time check
	// floors are the view's own per-subject floors: the pin's
	// and the floor of any older set that still carries a table. They only
	// go up. A newer root-signed set cannot lower them. The roster
	// verifier's watermark (roster.Open, on disk) is the other half: it
	// refuses every list below the newest one installed.
	floors map[string]uint64
}

// RootSignedPurposes are the key sets the offline root signs. After a root
// handover the new root re-signs the current set of each one before the
// overlap ends (roottrust.RunbookStep).
// It is the registry's list (roottrust.KeySetPurposes).
var RootSignedPurposes = roottrust.KeySetPurposes

// RootHealth is the state of the root that signed the set a view holds.
type RootHealth = roottrust.Health

// RootHealth reports the root that signed the held set. It logs once per
// root when the overlap ends soon. Verifiers expose it on their health and
// metrics surface.
func (v *View) RootHealth() RootHealth {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.rootHealthLocked()
}

func (v *View) rootHealthLocked() RootHealth {
	h := RootHealth{Purpose: v.purpose}
	root, until, soon, ok := roottrust.HealthOf(v.roots, v.signed)
	if !ok {
		return h
	}
	h.Root, h.OverlapUntil, h.EndsSoon = root, until, soon
	if soon && v.warned != root {
		v.warned = root
		log.Printf("keys: the %s key set is signed only by root %s, whose overlap ends %s: the new root must re-sign it before then (%s)",
			v.purpose, root, until.UTC().Format(time.RFC3339), roottrust.RunbookStep)
	}
	return h
}

// NewView pins the root public key and the install-time document. It keeps
// what it learns in memory only, so a restart falls back to the install
// pin. Production verifiers use NewViewWithState.
func NewView(p signer.Purpose, rootPub crypto.PublicKey, rootAlg signer.Algorithm, pinned Doc) (*View, error) {
	roots, err := roottrust.Pinned(rootPub, rootAlg)
	if err != nil {
		return nil, err
	}
	return newView(p, roots, pinned)
}

// NewViewRoots is NewViewWithState for a verifier that follows a root
// handover: roots (a roottrust.Trust) says which roots sign a key set now.
func NewViewRoots(p signer.Purpose, roots roottrust.Verifier, pinned Doc, path string) (*View, error) {
	if roots == nil {
		return nil, ErrState
	}
	return newViewWithState(p, roots, pinned, path)
}

// NewViewRootsMemory is NewView over the root chain: memory only.
func NewViewRootsMemory(p signer.Purpose, roots roottrust.Verifier, pinned Doc) (*View, error) {
	if roots == nil {
		return nil, ErrState
	}
	return newView(p, roots, pinned)
}

func newView(p signer.Purpose, roots roottrust.Verifier, pinned Doc) (*View, error) {
	if pinned.Purpose != p {
		return nil, fmt.Errorf("%w: pinned doc is %s, view is %s", signer.ErrWrongPurpose, pinned.Purpose, p)
	}
	v := &View{purpose: p, roots: roots, removed: map[string]bool{}}
	raw, _ := json.Marshal(pinned)
	if err := v.install(pinned, raw); err != nil {
		return nil, err
	}
	return v, nil
}

// NewViewWithState is NewView plus a durable watermark.
// The view stores the last root-signed key set it accepted at path, and
// reloads it at start. So a restart never falls back to keys that a reset
// removed, and never accepts a version lower than the last one it saw. An
// unreadable or wrongly signed state file fails closed.
func NewViewWithState(p signer.Purpose, rootPub crypto.PublicKey, rootAlg signer.Algorithm, pinned Doc, path string) (*View, error) {
	roots, err := roottrust.Pinned(rootPub, rootAlg)
	if err != nil {
		return nil, err
	}
	return newViewWithState(p, roots, pinned, path)
}

func newViewWithState(p signer.Purpose, roots roottrust.Verifier, pinned Doc, path string) (*View, error) {
	v, err := newView(p, roots, pinned)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("%w: empty state path", ErrState)
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	default:
		// The view's own state is checked against the chain as it is
		// now: a set signed only by a root whose overlap ended fails
		// closed, and the error names the runbook step.
		d, payload, err := v.check(string(b))
		if err != nil && !errors.Is(err, ErrNoChange) {
			return nil, fmt.Errorf("%w: %w", ErrState, err)
		}
		if err == nil {
			if err := v.install(d, payload); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrState, err)
			}
		}
		v.signed = string(b)
		v.held.Set(v.roots, v.signed)
		v.rootHealthLocked()
	}
	v.statePath = path
	return v, nil
}

func (v *View) install(d Doc, raw []byte) error {
	ks := map[string]viewKey{}
	removed := map[string]bool{}
	for r := range v.removed {
		removed[r] = true
	}
	for _, r := range d.Removed {
		removed[r] = true
	}
	for _, k := range d.Keys {
		if removed[k.Kid] {
			return fmt.Errorf("%w: doc re-adds %s", ErrKeyRemoved, k.Kid)
		}
		info := signer.KeyInfo{ID: k.Kid, Purpose: d.Purpose, Algorithm: k.Alg, PublicDER: k.PublicDER}
		pub, err := info.PublicKey()
		if err != nil {
			return err
		}
		ks[k.Kid] = viewKey{pub: pub, alg: k.Alg}
	}
	v.doc, v.raw, v.keys, v.removed = d.clone(), raw, ks, removed
	for subject, f := range d.MinVersions {
		v.raiseFloorLocked(subject, f)
	}
	return nil
}

// raiseFloorLocked raises the floor of subject to f; it never lowers it.
func (v *View) raiseFloorLocked(subject string, f uint64) {
	if f == 0 || subject == "" || v.floors[subject] >= f {
		return
	}
	if v.floors == nil {
		v.floors = map[string]uint64{}
	}
	v.floors[subject] = f
}

// check verifies a signed key-set document against the current view and
// returns it when it may be installed. Only the offline root signs a key
// set the view accepts.
func (v *View) check(signed string) (Doc, []byte, error) {
	h, err := jws.PeekHeader(signed)
	if err != nil {
		return Doc{}, nil, err
	}
	if h.Typ != DocType {
		return Doc{}, nil, ErrWrongType
	}
	switch h.Purpose {
	case string(signer.PurposeKeySetRoot):
	case string(v.purpose):
		return Doc{}, nil, fmt.Errorf("%w: key sets are signed by the offline root, not by a %s key", ErrRootRequired, h.Purpose)
	default:
		return Doc{}, nil, fmt.Errorf("%w: doc signed by a %s key", signer.ErrWrongPurpose, h.Purpose)
	}
	payload, err := roottrust.VerifyArtifact(v.roots, roottrust.ArtKeySet, signed)
	if err != nil {
		return Doc{}, nil, err
	}
	if r, held := roottrust.RankOf(v.roots, signed), v.held.Rank(); r < held {
		return Doc{}, nil, fmt.Errorf("%w: rank %d, held %d", ErrRootRank, r, held)
	}
	var d Doc
	if err := json.Unmarshal(payload, &d); err != nil {
		return Doc{}, nil, err
	}
	if d.Purpose != v.purpose {
		return Doc{}, nil, fmt.Errorf("%w: doc for %s", signer.ErrWrongPurpose, d.Purpose)
	}
	if v.purpose.Rotates() {
		na, nn := 0, 0
		for _, k := range d.Keys {
			switch k.State {
			case StateActive:
				na++
			case StateNext:
				nn++
			}
		}
		if na != 1 || nn != 1 {
			return Doc{}, nil, fmt.Errorf("%w: %d active, %d standby", ErrBadKeySet, na, nn)
		}
	}
	switch {
	case d.Epoch < v.doc.Epoch:
		return Doc{}, nil, ErrRollback
	case d.Epoch == v.doc.Epoch && d.Version < v.doc.Version:
		return Doc{}, nil, ErrRollback
	case d.Epoch == v.doc.Epoch && d.Version == v.doc.Version:
		if bytes.Equal(payload, v.raw) {
			return Doc{}, nil, ErrNoChange
		}
		return Doc{}, nil, ErrRollback
	}
	// A newer set never swaps the public half of a key the view
	// already trusts and never brings a removed key back. Floors are the
	// view's own: a set with no table, or with a lower one,
	// lowers nothing.
	if err := checkSuccessorKeys(v.doc, d); err != nil {
		return Doc{}, nil, err
	}
	return d, payload, nil
}

// Update applies a root-signed full key set with a higher (epoch, version)
// than the current one. A durable view writes the document to its state
// file before it installs it.
func (v *View) Update(signed string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, payload, err := v.check(signed)
	if err != nil {
		return err
	}
	// Dry-run the install so that a refused doc never reaches the state file.
	probe := &View{purpose: v.purpose, removed: v.removed}
	if err := probe.install(d, payload); err != nil {
		return err
	}
	if v.statePath != "" {
		if err := writeAtomic(v.statePath, []byte(signed)); err != nil {
			return fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	if err := v.install(d, payload); err != nil {
		return err
	}
	v.signed = signed
	v.held.Set(v.roots, v.signed)
	v.rootHealthLocked() // logs when the new set's root ends soon
	return nil
}

// writeAtomic writes b to path through a synced temporary file and rename.
func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Version returns the (epoch, version) of the installed key set.
func (v *View) Version() (uint64, uint64) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.doc.Epoch, v.doc.Version
}

// Lookup returns the public key and algorithm for kid.
func (v *View) Lookup(kid string) (crypto.PublicKey, signer.Algorithm, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.removed[kid] {
		return nil, "", ErrKeyRemoved
	}
	if err := v.held.Check(v.roots, string(v.purpose)+" key set"); err != nil {
		return nil, "", err
	}
	k, ok := v.keys[kid]
	if !ok {
		return nil, "", ErrUnknownKey
	}
	return k.pub, k.alg, nil
}

func (v *View) Purpose() signer.Purpose { return v.purpose }

// MinVersion is the local floor for subject: the
// higher of the install pin's floor and the floor of any set that carried
// one. 0 when none.
func (v *View) MinVersion(subject string) uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.floors[subject]
}

// RaiseFloor raises the local floor of subject to f. It never lowers one. The
// floor lives in memory, from the install pin and from the sets the view
// accepted; a node that lost its state calls this with the pin that its
// token fetches.
func (v *View) RaiseFloor(subject string, f uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.raiseFloorLocked(subject, f)
}

// Signed returns the root-signed document the view last accepted through
// Update or its state file, or "" when it holds only the install pin.
func (v *View) Signed() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.signed
}

// JWKS is the public key set for this purpose.
func (v *View) JWKS() jose.JSONWebKeySet {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var s jose.JSONWebKeySet
	for _, k := range v.doc.Keys {
		s.Keys = append(s.Keys, jose.JSONWebKey{Key: v.keys[k.Kid].pub, KeyID: k.Kid, Algorithm: string(k.Alg), Use: "sig"})
	}
	return s
}
