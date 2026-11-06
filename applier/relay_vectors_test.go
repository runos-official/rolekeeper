package applier_test

// C6: the shared test vectors under testdata/relay/. Conductor copies the
// directory. Its own gzip of body.json must pass the same checks: the
// signature covers the body bytes, the token id is their SHA-256, and the
// envelope rebuilt from token and body.gz is byte for byte envelope.json.
//
// Regenerate with ROID_UPDATE_VECTORS=1 go test ./applier -run TestRelayVectors.
// The files hold public data only (keys are generated for the vectors and
// the signing key is dropped). Every id is an example id.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
)

const vecDir = "testdata/relay"

type vecMeta struct {
	Now            time.Time `json:"now"`
	Account        string    `json:"account"`
	Cluster        string    `json:"cluster"`
	Nonce          string    `json:"nonce"`
	ContentDigest  string    `json:"content_digest"`
	BodySHA256     string    `json:"body_sha256"`
	EnvelopeSHA256 string    `json:"envelope_sha256"`
	BodyGzBytes    int       `json:"body_gz_bytes"`
}

func writeVec(t *testing.T, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(vecDir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readVec(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vecDir, name))
	if err != nil {
		t.Fatalf("%v (regenerate with ROID_UPDATE_VECTORS=1)", err)
	}
	return b
}

func generateVectors(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(vecDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := newRelayRig(t)
	raw := r.envelope(t, bundle.Bundle{Version: 7, Namespaces: []string{"apps"}, Objects: append(denyObjs(t, r.now), binding("alice"))})
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	const nonce = "dmVjdG9yLW5vbmNlLTAwMDE" // 22 chars of base64url
	v, err := bundle.NewVerifier(r.trust, r.clock, filepath.Join(t.TempDir(), "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	v.ExpectAccount("acct-a")
	ver, err := v.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzipOf(t, env.Body)
	trust, _ := json.MarshalIndent(r.trust, "", "  ")
	meta, _ := json.MarshalIndent(vecMeta{Now: r.now, Account: "acct-a", Cluster: "cl-1", Nonce: nonce, ContentDigest: ver.Digest,
		BodySHA256: sha(env.Body), EnvelopeSHA256: sha(raw), BodyGzBytes: len(gz)}, "", "  ")
	writeVec(t, "trust.json", append(trust, '\n'))
	writeVec(t, "meta.json", append(meta, '\n'))
	writeVec(t, "envelope.json", raw)
	writeVec(t, "token.txt", []byte(env.Bundle+"\n"))
	writeVec(t, "body.json", env.Body)
	writeVec(t, "body.sha256", []byte(sha(env.Body)+"\n"))
	writeVec(t, "body.gz", gz)
	writeVec(t, "fresh.jwt", []byte(r.freshFor(t, nonce, raw)+"\n"))
	writeVec(t, "refusal-cluster.jwt", []byte(r.refusal(t, "cluster")+"\n"))
	writeVec(t, "refusal-retired.jwt", []byte(r.refusal(t, "retired")+"\n"))
}

func TestRelayVectors(t *testing.T) {
	if os.Getenv("ROID_UPDATE_VECTORS") == "1" {
		generateVectors(t)
	}
	var meta vecMeta
	if err := json.Unmarshal(readVec(t, "meta.json"), &meta); err != nil {
		t.Fatal(err)
	}
	var trust bundle.Trust
	if err := json.Unmarshal(readVec(t, "trust.json"), &trust); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return meta.Now }
	v, err := bundle.NewVerifier(trust, clock, filepath.Join(t.TempDir(), "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	v.ExpectAccount(meta.Account)
	line := func(name string) string { return strings.TrimSpace(string(readVec(t, name))) }
	body, token, gz, envelope := readVec(t, "body.json"), line("token.txt"), readVec(t, "body.gz"), readVec(t, "envelope.json")

	if sha(body) != line("body.sha256") || sha(body) != meta.BodySHA256 || sha(envelope) != meta.EnvelopeSHA256 || len(gz) != meta.BodyGzBytes {
		t.Fatal("the digests in the vectors do not match the files")
	}
	// What the applier does with the two ConfigMap keys.
	rebuilt, err := bundle.RebuildEnvelope(token, gz)
	if err != nil {
		t.Fatal(err)
	}
	if string(rebuilt) != string(envelope) {
		t.Fatal("token plus body.gz does not rebuild the envelope roid served")
	}
	ver, err := v.Verify(rebuilt)
	if err != nil || ver.Digest != meta.ContentDigest || ver.Bundle.Cluster != meta.Cluster || ver.Bundle.Account != meta.Account {
		t.Fatalf("verify: %+v %v", ver, err)
	}
	// Any gzip of body.json (conductor's own) rebuilds the same envelope.
	own, err := bundle.GzipBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := bundle.RebuildEnvelope(token, own); err != nil || string(again) != string(envelope) {
		t.Fatalf("a gzip of the body made here does not rebuild the envelope: %v", err)
	}
	if err := v.VerifyFresh(line("fresh.jwt"), meta.Nonce, meta.ContentDigest); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyFresh(line("fresh.jwt"), "bm90LXRoZS1ub25jZS0wMDAwMA", meta.ContentDigest); err == nil {
		t.Fatal("a fresh token verified for another nonce")
	}
	for name, want := range map[string]string{"refusal-cluster.jwt": "cluster", "refusal-retired.jwt": "retired"} {
		if got, err := v.VerifyRefusal(line(name)); err != nil || got != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	// Neither relay token is a bundle, and the bundle token is neither.
	if _, err := v.VerifyRefusal(token); err == nil {
		t.Fatal("the bundle token verified as a refusal")
	}
	if err := v.VerifyFresh(token, meta.Nonce, meta.ContentDigest); err == nil {
		t.Fatal("the bundle token verified as a fresh token")
	}
}
