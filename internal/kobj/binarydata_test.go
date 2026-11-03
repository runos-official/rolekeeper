package kobj_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/runos-official/rolekeeper/internal/kobj"
)

// The relay ConfigMap holds the gzip body in binaryData. The
// object model carries it through the REST client in both directions.
func TestBinaryDataRoundTripsThroughTheLiveJSONAndTheManifest(t *testing.T) {
	live := []byte(`{"kind":"ConfigMap","metadata":{"name":"b","namespace":"n","resourceVersion":"7"},
		"data":{"token":"t"},"binaryData":{"body.gz":"H4sIAAAA"}}`)
	o, err := kobj.FromJSON(live)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o.BinaryData["body.gz"], []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00}) || o.Data["token"] != "t" {
		t.Fatalf("live object: %+v", o)
	}
	var m struct {
		BinaryData map[string]string `json:"binaryData"`
		Data       map[string]string `json:"data"`
	}
	if err := json.Unmarshal(o.JSON(), &m); err != nil || m.BinaryData["body.gz"] != "H4sIAAAA" || m.Data["token"] != "t" {
		t.Fatalf("manifest %s (%v)", o.JSON(), err)
	}
}

func TestAConfigMapWithoutBinaryDataKeepsItsOldManifest(t *testing.T) {
	o := kobj.Object{Kind: kobj.KindConfigMap, Name: "c", Namespace: "n", Data: map[string]string{"a": "b"}}
	if bytes.Contains(o.JSON(), []byte("binaryData")) {
		t.Fatalf("manifest %s", o.JSON())
	}
	// A bundle object marshals without the field, so signed bundles stay
	// byte for byte what roid signed before.
	raw, _ := json.Marshal(o)
	if bytes.Contains(raw, []byte("BinaryData")) {
		t.Fatalf("object JSON %s", raw)
	}
}

func TestDiffSeesAChangedBinaryDataAndCloneCopiesIt(t *testing.T) {
	a := kobj.Object{Kind: kobj.KindConfigMap, Name: "c", Namespace: "n", BinaryData: map[string][]byte{"k": []byte("one")}}
	b := a.Clone()
	if d := kobj.Diff(a, b); len(d) != 0 {
		t.Fatalf("clone differs: %v", d)
	}
	b.BinaryData["k"][0] = 'X'
	if string(a.BinaryData["k"]) != "one" {
		t.Fatal("Clone shares the binaryData bytes")
	}
	if d := kobj.Diff(a, b); len(d) != 1 || d[0] != "data" {
		t.Fatalf("diff %v, want data", d)
	}
}
