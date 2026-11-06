package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
	"github.com/runos-official/rolekeeper/signer/revlog"
	"github.com/runos-official/rolekeeper/signer/roottrust"
	"time"
)

// The offline root never joins the identity process.
// The online Manager and the offline ceremony tool talk through two files:
//
//	PreparePublish / PrepareCompromise  -> Request (the document to sign)
//	ceremony tool signs it offline      -> signed key set (compact JWS)
//	CommitPublish / CommitCompromise    <- the signed key set
//
// The Manager keeps the Request it handed out. A commit must carry a
// signature by the root over exactly that document. A signature over any
// other document, by any other key, or a second commit of the same request,
// is refused, and a refused commit changes nothing.

// RequestKind says which ceremony a Request asks for.
type RequestKind string

const (
	RequestPublish    RequestKind = "publish"    // add the next standby, promote nothing
	RequestCompromise RequestKind = "compromise" // remove one key, new epoch
)

// Request is what the offline side signs. DocJSON is the exact byte string
// to put in the JWS payload. Doc is the same document in signed form: it
// never holds a floor table. The Manager keeps its live floors
// apart and adds them back when it commits the request.
type Request struct {
	Kind    RequestKind    `json:"kind"`
	Purpose signer.Purpose `json:"purpose"`
	Kid     string         `json:"kid,omitempty"` // the key to remove, for a compromise
	Doc     Doc            `json:"doc"`
	DocJSON []byte         `json:"doc_json"`
	// Annex is set on the one request that takes the old floor table out
	// of the root-signed set: it holds roid's live floors for the
	// custodians and the ceremony log. It is not part of the signed bytes.
	Annex *FloorAnnex `json:"annex,omitempty"`
}

// FloorAnnex is the floor table that leaves the root-signed set,
// as roid holds it live when it prepares the request. The ceremony checks
// every floor it signed before against it and logs its digest. It is for
// the custodians and the log. No verifier receives it.
type FloorAnnex struct {
	Floors map[string]uint64 `json:"floors"`
	// SHA256 is the hex SHA-256 of Floors in JSON form (keys sorted).
	SHA256 string `json:"sha256"`
}

// NewFloorAnnex builds the annex of floors with its digest.
func NewFloorAnnex(floors map[string]uint64) *FloorAnnex {
	f := make(map[string]uint64, len(floors))
	for k, v := range floors {
		f[k] = v
	}
	a := &FloorAnnex{Floors: f}
	a.SHA256 = a.Digest()
	return a
}

// Digest is the hex SHA-256 of the floors in JSON form. Go writes map keys
// in sorted order, so equal tables give equal digests.
func (a FloorAnnex) Digest() string {
	b, _ := json.Marshal(a.Floors)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var (
	// ErrNoRequest: nothing is waiting for a signature for this purpose.
	ErrNoRequest = errors.New("keys: no request waiting for the root")
	// ErrRequestMismatch: the root signed a document other than the request.
	ErrRequestMismatch = errors.New("keys: signed document is not the one requested")
)

// PreparePublish builds the next full key set for p and remembers it. It
// does not sign and does not change the key set.
func (m *Manager) PreparePublish(_ context.Context, p signer.Purpose) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.prepPublish(p)
	if err != nil {
		return Request{}, err
	}
	return m.remember(RequestPublish, p, "", d, false)
}

// PreparePublishRetiringFloors is PreparePublish for the one request that
// takes the old floor table out of the root-signed set. The
// request carries roid's live floors as its annex. The ceremony refuses it
// unless every floor it signed before is at or below the annex, and it
// accepts the retirement once per purpose.
func (m *Manager) PreparePublishRetiringFloors(_ context.Context, p signer.Purpose) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.prepPublish(p)
	if err != nil {
		return Request{}, err
	}
	return m.remember(RequestPublish, p, "", d, true)
}

// PrepareCompromiseRetiringFloors is PrepareCompromise for a reset that
// also retires the floor table.
func (m *Manager) PrepareCompromiseRetiringFloors(ctx context.Context, p signer.Purpose, kid string) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.prepCompromise(ctx, p, kid)
	if err != nil {
		return Request{}, err
	}
	return m.remember(RequestCompromise, p, kid, d, true)
}

// PrepareCompromise builds the root-signed reset that removes kid and
// remembers it. It may create replacement keys in custody.
func (m *Manager) PrepareCompromise(ctx context.Context, p signer.Purpose, kid string) (Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.prepCompromise(ctx, p, kid)
	if err != nil {
		return Request{}, err
	}
	return m.remember(RequestCompromise, p, kid, d, false)
}

// remember keeps the request in signed form. d still holds the live
// floors, so the annex of a retiring request is taken from it here.
func (m *Manager) remember(k RequestKind, p signer.Purpose, kid string, d Doc, retire bool) (Request, error) {
	signed := d.SignedForm()
	raw, err := json.Marshal(signed)
	if err != nil {
		return Request{}, err
	}
	r := &Request{Kind: k, Purpose: p, Kid: kid, Doc: signed, DocJSON: raw}
	if retire {
		r.Annex = NewFloorAnnex(d.MinVersions)
	}
	m.pending[p] = r
	return *r, nil
}

// withLiveFloors is the document a request commits: the signed form plus
// the floors the manager holds now. A floor raised while the request
// waited stays (floors only go up).
func withLiveFloors(signed, cur Doc) Doc {
	d := signed.clone()
	d.MinVersions = cur.clone().MinVersions
	return d
}

// verifyPending checks the signature and that it covers the pending request.
func (m *Manager) verifyPending(p signer.Purpose, k RequestKind, signed string, roots roottrust.Verifier) (*Request, error) {
	r := m.pending[p]
	if r == nil || r.Kind != k {
		return nil, ErrNoRequest
	}
	h, err := jws.PeekHeader(signed)
	if err != nil {
		return nil, err
	}
	if h.Typ != DocType {
		return nil, ErrWrongType
	}
	if h.Purpose != string(signer.PurposeKeySetRoot) {
		return nil, fmt.Errorf("%w: signed by a %s key, not the offline root", ErrRootRequired, h.Purpose)
	}
	if roots == nil {
		return nil, fmt.Errorf("%w: no offline root is pinned", ErrRootRequired)
	}
	payload, err := roottrust.VerifyArtifact(roots, roottrust.ArtKeySet, signed)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payload, r.DocJSON) {
		return nil, ErrRequestMismatch
	}
	return r, nil
}

// checkRank refuses a set signed by an earlier root of the chain than the
// last root-signed set of p.
func (m *Manager) checkRank(p signer.Purpose, signed string, roots roottrust.Verifier) error {
	last := m.lastSigned[p]
	if last == "" {
		return nil
	}
	if lr, nr := roottrust.RankOf(roots, last), roottrust.RankOf(roots, signed); nr < lr {
		return fmt.Errorf("%w: rank %d, last %d", ErrRootRank, nr, lr)
	}
	return nil
}

// CommitPublish verifies that the offline root signed the pending publish
// request for p, then writes it to the log and applies it. rootPub is the
// pinned root public key; it is CommitPublishRoots with a one-root trust.
func (m *Manager) CommitPublish(p signer.Purpose, signed string, rootPub crypto.PublicKey, rootAlg signer.Algorithm) error {
	roots, err := roottrust.Pinned(rootPub, rootAlg)
	if err != nil {
		return err
	}
	return m.CommitPublishRoots(p, signed, roots)
}

// CommitPublishRoots is CommitPublish for a verifier that follows the root
// chain: roots says which roots sign now.
func (m *Manager) CommitPublishRoots(p signer.Purpose, signed string, roots roottrust.Verifier) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return err
	}
	r, err := m.verifyPending(p, RequestPublish, signed, roots)
	if err != nil {
		return err
	}
	if err := m.checkRank(p, signed, roots); err != nil {
		return err
	}
	cur, err := m.doc(p)
	if err != nil {
		return err
	}
	if r.Doc.Epoch != cur.Epoch || r.Doc.Version != cur.Version+1 {
		delete(m.pending, p)
		return fmt.Errorf("%w: the key set moved from version %d to %d while the request waited", ErrRequestMismatch, r.Doc.Version-1, cur.Version)
	}
	full := withLiveFloors(r.Doc, cur)
	if err := m.commit(revlog.KindKeySetPublished, string(p), full, full); err != nil {
		return err
	}
	m.lastSigned[p] = signed
	delete(m.pending, p)
	return nil
}

// CommitCompromise verifies that the offline root signed the pending
// compromise reset for p, writes it to the log, applies it and disables the
// removed key in custody.
func (m *Manager) CommitCompromise(p signer.Purpose, signed string, rootPub crypto.PublicKey, rootAlg signer.Algorithm) error {
	roots, err := roottrust.Pinned(rootPub, rootAlg)
	if err != nil {
		return err
	}
	return m.CommitCompromiseRoots(p, signed, roots)
}

// CommitCompromiseRoots is CommitCompromise over the root chain.
func (m *Manager) CommitCompromiseRoots(p signer.Purpose, signed string, roots roottrust.Verifier) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return err
	}
	r, err := m.verifyPending(p, RequestCompromise, signed, roots)
	if err != nil {
		return err
	}
	if err := m.checkRank(p, signed, roots); err != nil {
		return err
	}
	cur, err := m.doc(p)
	if err != nil {
		return err
	}
	if r.Doc.Epoch != cur.Epoch+1 {
		delete(m.pending, p)
		return fmt.Errorf("%w: the key set moved while the request waited", ErrRequestMismatch)
	}
	delete(m.pending, p)
	_, err = m.commitCompromise(context.Background(), r.Kid, withLiveFloors(r.Doc, cur), signed)
	return err
}

// AdoptPending makes req this manager's pending request for its purpose.
// A replica that did not prepare req uses it to commit a signature the
// offline root made for a request another replica prepared and stored. It
// accepts only a publish request whose DocJSON is exactly the next version
// of the current set: same purpose and epoch, version one above, the same
// keys with the same public halves, algorithms and states, every key
// published, the same removed list and the same floors. So adoption never
// brings in a key or a floor the set does not hold. The root signature over
// DocJSON is still checked at commit.
func (m *Manager) AdoptPending(req Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(); err != nil {
		return err
	}
	if req.Kind == RequestCompromise {
		return m.adoptCompromise(req)
	}
	if req.Kind != RequestPublish {
		return fmt.Errorf("%w: only a publish or compromise request can be adopted", ErrRequestMismatch)
	}
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(req.DocJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("%w: %v", ErrRequestMismatch, err)
	}
	if d.Purpose != req.Purpose {
		return fmt.Errorf("%w: request for %s holds a %s document", ErrRequestMismatch, req.Purpose, d.Purpose)
	}
	cur, err := m.doc(req.Purpose)
	if err != nil {
		return err
	}
	if d.Epoch != cur.Epoch || d.Version != cur.Version+1 {
		return fmt.Errorf("%w: document is epoch %d version %d, the set is at epoch %d version %d", ErrRequestMismatch, d.Epoch, d.Version, cur.Epoch, cur.Version)
	}
	if len(d.Keys) != len(cur.Keys) {
		return fmt.Errorf("%w: document holds %d keys, the set %d", ErrRequestMismatch, len(d.Keys), len(cur.Keys))
	}
	for _, k := range d.Keys {
		c := cur.Find(k.Kid)
		if c == nil || c.Alg != k.Alg || c.State != k.State || !bytes.Equal(c.PublicDER, k.PublicDER) || k.PublishedAt.IsZero() {
			return fmt.Errorf("%w: key %s differs from the set", ErrRequestMismatch, k.Kid)
		}
	}
	// A request is in signed form and holds no floor table. A
	// request that an older replica prepared may still hold the live one;
	// it must be the same table, and the commit keeps the live floors.
	if !sameStrings(d.Removed, cur.Removed) || (len(d.MinVersions) != 0 && !sameFloors(d.MinVersions, cur.MinVersions)) {
		return fmt.Errorf("%w: removed keys or floors differ from the set", ErrRequestMismatch)
	}
	if err := checkAnnex(req.Annex, cur); err != nil {
		return err
	}
	m.pending[req.Purpose] = &Request{Kind: RequestPublish, Purpose: req.Purpose, Doc: d, DocJSON: append([]byte(nil), req.DocJSON...), Annex: req.Annex}
	return nil
}

// adoptCompromise accepts a compromise reset another replica prepared. The
// document must be the next epoch of the current set at version 1, without
// req.Kid and with req.Kid added to the removed list. Every key it keeps
// must be in the current set unchanged (an announced standby may become
// active), and every new key must be in this manager's custody under the
// same purpose, algorithm and public half, and not disabled. Floors never
// go down. The caller holds m.mu.
func (m *Manager) adoptCompromise(req Request) error {
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(req.DocJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("%w: %v", ErrRequestMismatch, err)
	}
	if d.Purpose != req.Purpose {
		return fmt.Errorf("%w: request for %s holds a %s document", ErrRequestMismatch, req.Purpose, d.Purpose)
	}
	cur, err := m.doc(req.Purpose)
	if err != nil {
		return err
	}
	if d.Epoch != cur.Epoch+1 || d.Version != 1 {
		return fmt.Errorf("%w: a reset is epoch %d version 1, the document is epoch %d version %d", ErrRequestMismatch, cur.Epoch+1, d.Epoch, d.Version)
	}
	if req.Kid == "" || cur.Find(req.Kid) == nil || d.Find(req.Kid) != nil {
		return fmt.Errorf("%w: the reset must remove %q, a key of the current set", ErrRequestMismatch, req.Kid)
	}
	if !sameStrings(d.Removed, append(append([]string(nil), cur.Removed...), req.Kid)) {
		return fmt.Errorf("%w: the removed list is not the current one plus %s", ErrRequestMismatch, req.Kid)
	}
	if len(d.MinVersions) != 0 { // signed form holds none; an older replica's request may
		for k, v := range cur.MinVersions {
			if d.MinVersions[k] < v {
				return fmt.Errorf("%w: floor for %s goes down", ErrRequestMismatch, k)
			}
		}
	}
	if err := checkAnnex(req.Annex, cur); err != nil {
		return err
	}
	for _, k := range d.Keys {
		if k.PublishedAt.IsZero() {
			return fmt.Errorf("%w: key %s is not published", ErrRequestMismatch, k.Kid)
		}
		if c := cur.Find(k.Kid); c != nil {
			if c.Alg != k.Alg || !bytes.Equal(c.PublicDER, k.PublicDER) {
				return fmt.Errorf("%w: key %s differs from the set", ErrRequestMismatch, k.Kid)
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		info, err := m.backend.PublicKey(ctx, k.Kid)
		cancel()
		if err != nil || info.Purpose != req.Purpose || info.Algorithm != k.Alg || info.Disabled || !bytes.Equal(info.PublicDER, k.PublicDER) {
			return fmt.Errorf("%w: new key %s is not in custody as published", ErrRequestMismatch, k.Kid)
		}
	}
	m.pending[req.Purpose] = &Request{Kind: RequestCompromise, Purpose: req.Purpose, Kid: req.Kid, Doc: d, DocJSON: append([]byte(nil), req.DocJSON...), Annex: req.Annex}
	return nil
}

// checkAnnex holds the annex of an adopted request to the live set: its
// digest matches its floors, and no floor is above the one this manager
// holds (a floor only goes up, so a lower or equal annex is a table from
// an earlier moment). A request without an annex passes.
func checkAnnex(a *FloorAnnex, cur Doc) error {
	if a == nil {
		return nil
	}
	if a.SHA256 != a.Digest() {
		return fmt.Errorf("%w: the floor annex does not match its digest", ErrRequestMismatch)
	}
	for k, v := range a.Floors {
		if v > cur.MinVersions[k] {
			return fmt.Errorf("%w: the floor annex names a floor for %s above the live one", ErrRequestMismatch, k)
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameFloors(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
