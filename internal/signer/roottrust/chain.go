package roottrust

// The root chain: the pinned original root plus zero or more
// handover bundles, each signed by the root before it, each naming the next
// root, the end of the old root's overlap and a sequence number one above
// the link before it. Every verifier pins the same original root and reads
// the chain from its config (root.chain.json beside root.pub). Moving the
// root again only adds a link: no certificate, service registration or CA
// key changes, and no verifier is rebuilt.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
)

// ChainFileName is the chain file's name beside root.pub (the
// roid-signer-root ConfigMap key).
const ChainFileName = "root.chain.json"

// ChainVersion is the chain file format.
const ChainVersion = 1

var (
	ErrBadChain    = errors.New("roottrust: the root chain file is not acceptable")
	ErrMissingLink = errors.New("roottrust: the root chain misses a handover")
	ErrSequence    = errors.New("roottrust: a handover's sequence number goes back")
	ErrFork        = errors.New("roottrust: the root chain differs from the one this verifier holds")
	ErrOlderChain  = errors.New("roottrust: the root chain is older than the one this verifier holds")
)

// ChainFile is root.chain.json: the handover bundles, oldest first.
type ChainFile struct {
	V         int               `json:"v"`
	Handovers []json.RawMessage `json:"handovers"`
}

// EncodeChain writes a chain file from handover bundles, oldest first.
func EncodeChain(bundles [][]byte) ([]byte, error) {
	cf := ChainFile{V: ChainVersion, Handovers: []json.RawMessage{}}
	for _, b := range bundles {
		cf.Handovers = append(cf.Handovers, json.RawMessage(b))
	}
	out, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadChain, err)
	}
	return append(out, '\n'), nil
}

// DecodeChain reads a chain file strictly. Link i must carry sequence
// number i+1. It checks each link's form and signatures (a handover or an
// overlap cutoff), not whether the chain starts from a verifier's pin:
// InstallChain does.
func DecodeChain(chainJSON []byte) ([]Link, error) {
	var cf ChainFile
	dec := json.NewDecoder(bytes.NewReader(chainJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadChain, err)
	}
	if cf.V != ChainVersion {
		return nil, fmt.Errorf("%w: version %d", ErrBadChain, cf.V)
	}
	links := make([]Link, 0, len(cf.Handovers))
	for i, raw := range cf.Handovers {
		l, err := decodeLink(raw)
		if err != nil {
			return nil, fmt.Errorf("link %d: %w", i+1, err)
		}
		switch want := uint64(i + 1); {
		case l.Seq < want:
			return nil, fmt.Errorf("%w: link %d carries sequence %d", ErrSequence, want, l.Seq)
		case l.Seq > want:
			return nil, fmt.Errorf("%w: link %d carries sequence %d", ErrMissingLink, want, l.Seq)
		}
		links = append(links, l)
	}
	return links, nil
}

// Seq is the sequence number of the newest applied handover (0: none).
func (t *Trust) Seq() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return uint64(len(t.bundles))
}

// Bundles returns the applied handover bundles, oldest first.
func (t *Trust) Bundles() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([][]byte, len(t.bundles))
	for i, b := range t.bundles {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

// ChainJSON is the chain this verifier holds, as a chain file.
func (t *Trust) ChainJSON() ([]byte, error) { return EncodeChain(t.Bundles()) }

// InstallChain makes the chain file the chain this verifier follows. The
// chain must walk from the pinned root, link by link, and agree with every
// link the verifier already holds. A chain shorter than the held one is
// refused with ErrOlderChain and changes nothing; so is any refused chain.
// It returns the number of links it added.
func (t *Trust) InstallChain(chainJSON []byte) (int, error) {
	links, err := DecodeChain(chainJSON)
	if err != nil {
		return 0, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	held := len(t.bundles)
	for i := 0; i < held && i < len(links); i++ {
		if !bytes.Equal(statementOf(t.bundles[i]), links[i].Statement) {
			return 0, fmt.Errorf("%w: link %d", ErrFork, i+1)
		}
	}
	if len(links) < held {
		return 0, fmt.Errorf("%w: it has %d handovers, this verifier holds %d", ErrOlderChain, len(links), held)
	}
	if len(links) == held {
		return 0, nil
	}
	// Apply on a copy, so a link that fails leaves the trust as it was.
	c := &Trust{now: t.now, roots: append([]entry(nil), t.roots...), bundles: append([][]byte(nil), t.bundles...), gen: t.gen}
	for _, l := range links[held:] {
		if _, err := c.apply(l.Raw, false); err != nil {
			return 0, err
		}
	}
	if t.path != "" {
		if err := writeState(t.path, c.snapshot(nil)); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	t.roots, t.bundles, t.gen = c.roots, c.bundles, c.gen
	return len(links) - held, nil
}

// Config is what a service gives Load.
type Config struct {
	// Pin is the original root (root.pub).
	Pin Root
	// Chain is the chain file from the config (root.chain.json). Nil or
	// empty: no handover is configured.
	Chain []byte
	// StatePath keeps the highest chain this verifier accepted, so a
	// restart with an older config chain keeps it. Required unless OneShot.
	StatePath string
	// OneShot is a check that holds no trust across a restart (a report,
	// one checkpoint): it may go without StatePath.
	OneShot bool
	// DeferFloor: the caller adds links after Load (roid, from root_chain)
	// and calls CheckFloor itself.
	DeferFloor bool
	Now        func() time.Time
	// Logf reports a config chain older than the held one. Nil: silent.
	Logf func(format string, args ...any)
}

// Load builds the trust a service verifies root signatures with: the pin,
// the held chain (StatePath) and the config chain. An older config chain
// is reported and the held one kept; a fork or a bad chain fails closed.
func Load(c Config) (*Trust, error) {
	var t *Trust
	var err error
	if c.StatePath == "" && !c.OneShot {
		return nil, fmt.Errorf("%w: a verifier needs a state path, or it takes an older chain after a restart", ErrState)
	}
	if c.StatePath != "" {
		t, err = Open(c.Pin, c.StatePath, c.Now)
	} else {
		t, err = New(c.Pin, c.Now)
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(c.Chain)) > 0 {
		if _, err := t.InstallChain(c.Chain); err != nil {
			if !errors.Is(err, ErrOlderChain) {
				return nil, err
			}
			if c.Logf != nil {
				c.Logf("roottrust: the configured root chain is older than the held one; keeping the held chain (handover %d): %v", t.Seq(), err)
			}
		}
	}
	if !c.DeferFloor {
		if err := t.CheckFloor(); err != nil { // N-M1
			return nil, err
		}
	}
	return t, nil
}

// ReadChainBeside reads root.chain.json in the directory of the root
// public key file. A missing or empty file means no handover: nil, nil.
func ReadChainBeside(rootPubPath string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(rootPubPath), ChainFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	return b, nil
}

// PinKey is the Root record of a parsed root public key. An empty alg is
// taken from the key type (Ed25519: EdDSA, P-256: ES256).
func PinKey(pub crypto.PublicKey, alg signer.Algorithm) (Root, error) {
	if alg == "" {
		switch pub.(type) {
		case ed25519.PublicKey:
			alg = signer.AlgEdDSA
		case *ecdsa.PublicKey:
			alg = signer.AlgES256
		}
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Root{}, fmt.Errorf("roottrust: the pinned root: %w", err)
	}
	r := Root{Alg: alg, PublicDER: der}
	r.KeyID = "root-" + r.Fingerprint()
	return r, r.check()
}

// Pinned is a one-root verifier: the trust of a verifier with no chain.
func Pinned(pub crypto.PublicKey, alg signer.Algorithm) (*Trust, error) {
	r, err := PinKey(pub, alg)
	if err != nil {
		return nil, err
	}
	return New(r, nil)
}

func (r Root) check() error {
	_, err := r.key()
	return err
}

// OverlapWarning is how long before the end of a root's overlap a
// verifier warns that a set it holds is signed only by that root.
const OverlapWarning = 7 * 24 * time.Hour

// RunbookStep is the step that keeps verifiers working through a handover:
// the new root re-signs every key set before the overlap ends.
const RunbookStep = "the offline root runbook, step 5"

// RootHealth says which root signed compact and when that root's overlap
// ends (zero: it does not end, the root is current). endsSoon is true when
// the end is less than OverlapWarning away or past. A document no root of
// the chain signed is an error. It never makes a document acceptable:
// Verify decides that.
func (t *Trust) RootHealth(compact string) (root string, overlapUntil time.Time, endsSoon bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.roots {
		if _, err := jws.Verify(compact, e.pub, e.Alg); err == nil {
			soon := !e.until.IsZero() && !t.now().Add(OverlapWarning).Before(e.until)
			return e.Fingerprint(), e.until, soon, nil
		}
	}
	return "", time.Time{}, false, jws.ErrBadSignature
}

// Health is the state of the root that signed the set a verifier holds.
type Health struct {
	Purpose signer.Purpose `json:"purpose"`
	// Root is the fingerprint of the signing root; empty when the held set
	// is an unsigned install pin.
	Root string `json:"root,omitempty"`
	// OverlapUntil is when that root stops signing; zero: it is current.
	OverlapUntil time.Time `json:"overlap_until,omitempty"`
	// EndsSoon: the overlap ends within OverlapWarning, or has ended. The
	// new root must re-sign the set (RunbookStep).
	EndsSoon bool `json:"ends_soon"`
}

// HealthOf is RootHealth for any Verifier that has it. ok is false when v
// has none or no root of v signed compact.
func HealthOf(v Verifier, compact string) (root string, overlapUntil time.Time, endsSoon, ok bool) {
	h, has := v.(interface {
		RootHealth(string) (string, time.Time, bool, error)
	})
	if !has || compact == "" {
		return "", time.Time{}, false, false
	}
	r, u, s, err := h.RootHealth(compact)
	return r, u, s, err == nil
}

// HandoverBundle makes a complete handover bundle in one process that holds
// both roots: for tests and drills. A real handover signs each side in its
// own ceremony (the root ceremony tool).
func HandoverBundle(from, to *signer.Signer, seq uint64, issued time.Time, overlap time.Duration) ([]byte, error) {
	fr := Root{KeyID: from.KeyID(), Alg: from.Algorithm(), PublicDER: from.Info().PublicDER}
	tr := Root{KeyID: to.KeyID(), Alg: to.Algorithm(), PublicDER: to.Info().PublicDER}
	st, err := NewStatement(fr, tr, seq, issued, overlap)
	if err != nil {
		return nil, err
	}
	payload, err := st.Payload()
	if err != nil {
		return nil, err
	}
	o, err := SignSide(from, payload)
	if err != nil {
		return nil, err
	}
	n, err := SignSide(to, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Bundle{Statement: payload, Old: o, New: n})
}

// PinDER is the Root record of a pinned root given as PKIX DER, as the
// service trust files carry it.
func PinDER(alg signer.Algorithm, der []byte) (Root, error) {
	r := Root{Alg: alg, PublicDER: append([]byte(nil), der...)}
	r.KeyID = "root-" + r.Fingerprint()
	if err := r.check(); err != nil {
		return Root{}, fmt.Errorf("roottrust: the pinned root: %w", err)
	}
	return r, nil
}
