package keys_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
)

// keySetRoid serves one signed key set at /v1/keysets/{purpose}, or a
// status code when code is set.
type keySetRoid struct {
	mu     sync.Mutex
	signed string
	code   int
	body   string
}

func (k *keySetRoid) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if r.URL.Path != "/v1/keysets/"+string(signer.PurposeOperationGrant) {
		http.NotFound(w, r)
		return
	}
	if k.code != 0 {
		w.WriteHeader(k.code)
		return
	}
	if k.body != "" {
		_, _ = w.Write([]byte(k.body))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"signed": k.signed})
}

// A durable view that follows a compromise reset drops the removed key at
// once, and a view rebuilt from the same state file after a restart still
// refuses it, with roid unreachable.
func TestFollowAppliesAResetAndADurableViewKeepsItAfterARestart(t *testing.T) {
	f := setup(t)
	p := signer.PurposeOperationGrant
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgES256))
	state := filepath.Join(t.TempDir(), "operation-grant-keys.jws")
	v := must(keys.NewViewWithState(p, f.root.Public(), f.rootAlg, pinned, state))
	if !v.Durable() || f.view(t, p, pinned).Durable() {
		t.Fatal("Durable: want true for a view with state and false for one without")
	}
	src := &keySetRoid{}
	srv := httptest.NewServer(src)
	t.Cleanup(srv.Close)

	// No set yet changes nothing.
	if err := keys.Follow(f.ctx, srv.Client(), srv.URL, v); err != nil {
		t.Fatalf("follow with no set: %v", err)
	}
	bad := pinned.Active().Kid
	src.signed = must(f.m.Compromise(f.ctx, p, bad, f.root))
	if err := keys.Follow(f.ctx, srv.Client(), srv.URL+"/", v); err != nil {
		t.Fatalf("follow the reset: %v", err)
	}
	if _, _, err := v.Lookup(bad); !errors.Is(err, keys.ErrKeyRemoved) {
		t.Fatalf("after the reset the removed key looks up with %v, want ErrKeyRemoved", err)
	}
	// The same set again is no change.
	if err := keys.Follow(f.ctx, srv.Client(), srv.URL, v); err != nil {
		t.Fatalf("follow the same set again: %v", err)
	}

	// Restart with roid down: the state file keeps the reset.
	srv.Close()
	re := must(keys.NewViewWithState(p, f.root.Public(), f.rootAlg, pinned, state))
	if err := keys.Follow(f.ctx, nil, srv.URL, re); err == nil {
		t.Fatal("follow with roid down: want an error")
	}
	if _, _, err := re.Lookup(bad); !errors.Is(err, keys.ErrKeyRemoved) {
		t.Fatalf("after a restart the removed key looks up with %v, want ErrKeyRemoved", err)
	}
}

// Follow refuses what it cannot use: an error answer, a malformed body, a
// set signed by a leaf key instead of the root, and no view.
func TestFollowRefusesBadAnswers(t *testing.T) {
	f := setup(t)
	p := signer.PurposeOperationGrant
	pinned := must(f.m.Bootstrap(f.ctx, p, signer.AlgES256))
	v := f.view(t, p, pinned)
	src := &keySetRoid{}
	srv := httptest.NewServer(src)
	t.Cleanup(srv.Close)

	src.code = http.StatusServiceUnavailable
	if err := keys.Follow(f.ctx, srv.Client(), srv.URL, v); err == nil {
		t.Error("a 503 answer: want an error")
	}
	src.code, src.body = 0, "{not json"
	if err := keys.Follow(f.ctx, srv.Client(), srv.URL, v); err == nil {
		t.Error("a malformed body: want an error")
	}
	src.body, src.signed = "", "not-a-jws"
	if err := keys.Follow(f.ctx, srv.Client(), srv.URL, v); err == nil {
		t.Error("a set that is not a JWS: want an error")
	}
	if err := keys.Follow(f.ctx, srv.Client(), srv.URL, nil); err == nil {
		t.Error("no view: want an error")
	}
	if err := keys.Follow(f.ctx, srv.Client(), "http://[::1]:namedport", v); err == nil {
		t.Error("a bad base URL: want an error")
	}
}
