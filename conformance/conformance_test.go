package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/conformance"
)

var update = flag.Bool("update", false, "rewrite testdata/conformance from the generator")

var (
	vectorsPath  = filepath.Join("..", "testdata", "conformance", "vectors.json")
	checksumPath = filepath.Join("..", "testdata", "conformance", "vectors.sha256")
)

func loadFile(t *testing.T) conformance.File {
	t.Helper()
	f, err := conformance.Load(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// The vector file is frozen: this test is the one that reads it as the
// verifiers of today must. A release that makes it fail has changed what a
// verifier decides and needs a new vector version.
func TestEveryVectorGetsTheOutcomeTheFileExpects(t *testing.T) {
	f := loadFile(t)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if err := f.Check(c, t.TempDir()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTheFileHoldsBothAcceptedAndRefusedCasesOfEveryKind(t *testing.T) {
	f := loadFile(t)
	ids := map[string]bool{}
	accepted, refused := map[string]int{}, map[string]int{}
	for _, c := range f.Cases {
		if ids[c.ID] {
			t.Errorf("case id %q is used twice", c.ID)
		}
		ids[c.ID] = true
		if c.Description == "" {
			t.Errorf("%s has no description", c.ID)
		}
		if c.Expect.OK {
			accepted[c.Kind]++
			if c.Expect.Error != "" {
				t.Errorf("%s expects success and an error", c.ID)
			}
		} else {
			refused[c.Kind]++
			if c.Expect.Error == "" {
				t.Errorf("%s expects a refusal and names no error code", c.ID)
			}
		}
	}
	for _, kind := range []string{conformance.KindBundle, conformance.KindFresh, conformance.KindRefusal, conformance.KindKeySet} {
		if accepted[kind] == 0 || refused[kind] == 0 {
			t.Errorf("kind %s: %d accepted and %d refused cases; it needs both", kind, accepted[kind], refused[kind])
		}
	}
	if len(f.Cases) < 30 {
		t.Errorf("only %d cases", len(f.Cases))
	}
}

func TestTheFileSaysThatItsKeysAreTestOnly(t *testing.T) {
	f := loadFile(t)
	if !strings.Contains(f.Notice, "TEST-ONLY") {
		t.Fatalf("notice: %q", f.Notice)
	}
	raw, _ := os.ReadFile(vectorsPath)
	for _, forbidden := range []string{"PRIVATE KEY", "\"d\":", "\"seed\""} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("the vector file holds %q: it must hold public data only", forbidden)
		}
	}
}

func TestTheFileMatchesItsChecksum(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(checksumPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(want)); len(got) != 2 || got[0] != sum(raw) || got[1] != "vectors.json" {
		t.Fatalf("vectors.sha256 does not describe vectors.json (it holds %q, the file is %s)", want, sum(raw))
	}
}

// The generator is deterministic: same keys, same clock, same bytes. If this
// fails while the test above passes, the signing code changed what it writes
// and the next release needs a new vector version.
func TestFileIsWhatTheGeneratorWrites(t *testing.T) {
	got := generate(t)
	if *update {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(checksumPath, []byte(sum(got)+"  vectors.json\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("rewrote testdata/conformance")
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (generate with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the generator writes other bytes than testdata/conformance/vectors.json; signing or encoding changed")
	}
	again := generate(t)
	if !bytes.Equal(got, again) {
		t.Fatal("the generator is not deterministic: two runs wrote different bytes")
	}
}

// Tamper proof beyond the cases in the file: take every accepted case and
// change it in each place that a signature or a digest covers.

func acceptedOfKind(t *testing.T, f conformance.File, kind string) []conformance.Case {
	t.Helper()
	var out []conformance.Case
	for _, c := range f.Cases {
		if c.Kind == kind && c.Expect.OK {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no accepted %s case", kind)
	}
	return out
}

// flip changes character i of s to another character of the base64url alphabet.
func flip(s string, i int) string {
	b := []byte(s)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func signatureStart(tok string) int { return strings.LastIndexByte(tok, '.') + 1 }

func TestChangingAnyCharacterOfABundleSignatureIsRefused(t *testing.T) {
	f := loadFile(t)
	for _, c := range acceptedOfKind(t, f, conformance.KindBundle) {
		tok := c.Envelope.Bundle
		start := signatureStart(tok)
		// The last character of a 64-byte signature carries padding bits, so
		// a change there may decode to the same bytes. Every other one counts.
		for i := start; i < len(tok)-1; i++ {
			tampered := c
			env := *c.Envelope
			env.Bundle = flip(tok, i)
			tampered.Envelope = &env
			got, err := f.Run(tampered, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if got.OK {
				t.Fatalf("%s: signature character %d changed and the bundle was accepted", c.ID, i-start)
			}
		}
	}
}

func TestChangingAnyByteOfABundleBodyIsRefused(t *testing.T) {
	f := loadFile(t)
	for _, c := range acceptedOfKind(t, f, conformance.KindBundle) {
		for i := range c.Envelope.Body {
			env := *c.Envelope
			env.Body = append([]byte(nil), c.Envelope.Body...)
			env.Body[i] ^= 0x01
			tampered := c
			tampered.Envelope = &env
			got, err := f.Run(tampered, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if got.OK {
				t.Fatalf("%s: body byte %d changed and the bundle was accepted", c.ID, i)
			}
		}
	}
}

func TestChangingAnyCharacterOfAHeaderOrClaimsIsRefused(t *testing.T) {
	f := loadFile(t)
	for _, c := range acceptedOfKind(t, f, conformance.KindBundle) {
		tok := c.Envelope.Bundle
		for i := 0; i < signatureStart(tok)-1; i++ {
			if tok[i] == '.' {
				continue
			}
			tampered := c
			env := *c.Envelope
			env.Bundle = flip(tok, i)
			tampered.Envelope = &env
			got, err := f.Run(tampered, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if got.OK {
				t.Fatalf("%s: character %d of the header or claims changed and the bundle was accepted", c.ID, i)
			}
		}
	}
}

func TestChangingARelayTokenIsRefused(t *testing.T) {
	f := loadFile(t)
	for _, kind := range []string{conformance.KindFresh, conformance.KindRefusal} {
		for _, c := range acceptedOfKind(t, f, kind) {
			for i := 0; i < len(c.Token)-1; i++ {
				if c.Token[i] == '.' {
					continue
				}
				tampered := c
				tampered.Token = flip(c.Token, i)
				got, err := f.Run(tampered, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if got.OK {
					t.Fatalf("%s: character %d changed and the token was accepted", c.ID, i)
				}
			}
		}
	}
}

func TestAnAcceptedKeySetIsRefusedWhenAnyCharacterChanges(t *testing.T) {
	f := loadFile(t)
	for _, c := range acceptedOfKind(t, f, conformance.KindKeySet) {
		for i := 0; i < len(c.Signed)-1; i++ {
			if c.Signed[i] == '.' {
				continue
			}
			tampered := c
			tampered.Signed = flip(c.Signed, i)
			got, err := f.Run(tampered, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if got.OK {
				t.Fatalf("%s: character %d changed and the key set was accepted", c.ID, i)
			}
		}
	}
}

func TestACaseOfAnotherAccountOrClusterIsNeverAccepted(t *testing.T) {
	f := loadFile(t)
	for _, c := range f.Cases {
		if !c.Expect.OK || c.Kind == conformance.KindKeySet {
			continue
		}
		for name, mutate := range map[string]func(*conformance.Case){
			"account": func(x *conformance.Case) { x.Account = "acct-other" },
			"cluster": func(x *conformance.Case) { x.Cluster = "cl-other" },
		} {
			tampered := c
			mutate(&tampered)
			got, err := f.Run(tampered, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if got.OK {
				t.Errorf("%s: accepted for another %s", c.ID, name)
			}
		}
	}
}

func TestCodeNamesEachRefusalTheSameWay(t *testing.T) {
	cases := map[error]string{
		bundle.ErrFormat:  "bad_format",
		bundle.ErrSubject: "not_an_rbac_bundle",
		bundle.ErrDigest:  "digest_mismatch",
		bundle.ErrCluster: "wrong_cluster",
		bundle.ErrAccount: "wrong_account",
		bundle.ErrFresh:   "fresh_token_mismatch",
		bundle.ErrRefusal: "bad_refusal",
	}
	for err, want := range cases {
		if got := conformance.Code(err); got != want {
			t.Errorf("Code(%v) = %q, want %q", err, got, want)
		}
		if got := conformance.Code(errors.Join(errors.New("context"), err)); got != want {
			t.Errorf("a wrapped %v is %q, want %q", err, got, want)
		}
	}
	if conformance.Code(nil) != "" || conformance.Code(errors.New("other")) != "invalid" {
		t.Error("nil or an unknown error has the wrong code")
	}
}

func TestLoadRefusesAFileThatIsNotFormatOne(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := conformance.Load(write("v9.json", `{"format": 9}`)); err == nil {
		t.Error("format 9 loaded")
	}
	if _, err := conformance.Load(write("broken.json", `{`)); err == nil {
		t.Error("broken JSON loaded")
	}
	if _, err := conformance.Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing file loaded")
	}
}

func TestRunRefusesACaseItCannotRun(t *testing.T) {
	f := loadFile(t)
	for name, c := range map[string]conformance.Case{
		"unknown kind":    {ID: "x", Kind: "other"},
		"bundle no input": {ID: "y", Kind: conformance.KindBundle},
	} {
		if _, err := f.Run(c, t.TempDir()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if err := f.Check(conformance.Case{ID: "z", Kind: conformance.KindRefusal, Token: "x.y.z", Expect: conformance.Expect{OK: true}}, t.TempDir()); err == nil {
		t.Error("a mismatch was not reported")
	}
}

func TestTheFileIsPlainJSONThatRoundTrips(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f conformance.File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	again, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(again, '\n'), raw) {
		t.Fatal("the file is not what the types write back: a field is lost or reordered")
	}
}
