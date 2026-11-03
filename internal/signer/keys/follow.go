package keys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Durable reports whether the view keeps the key set it accepted in a
// state file (NewViewWithState). Only a durable view keeps a compromise
// reset across a restart.
func (v *View) Durable() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.statePath != ""
}

// Follow fetches the newest root-signed key set of the view's purpose from
// roid (GET {base}/v1/keysets/{purpose}) and applies it with Update. A
// publish ceremony adds the next key, a compromise reset removes one. A set
// the view holds already, an older one, or no set yet changes nothing. The
// transport adds no trust: only the offline root signature does. hc nil
// uses a client with a 10 s timeout.
func Follow(ctx context.Context, hc *http.Client, base string, v *View) error {
	if v == nil {
		return errors.New("keys: follow: no view")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	u := strings.TrimRight(base, "/") + "/v1/keysets/" + url.PathEscape(string(v.Purpose()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("keys: follow %s: %w", v.Purpose(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keys: follow %s: roid answered %d", v.Purpose(), resp.StatusCode)
	}
	var body struct {
		Signed string `json:"signed"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return fmt.Errorf("keys: follow %s: malformed reply", v.Purpose())
	}
	if body.Signed == "" {
		return nil
	}
	if err := v.Update(body.Signed); err != nil && !errors.Is(err, ErrNoChange) && !errors.Is(err, ErrRollback) {
		return err
	}
	return nil
}
