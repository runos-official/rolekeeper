package kubeapi_test

import (
	"context"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/internal/kobj"
)

// The relay watch loop reads only the metadata of two ConfigMaps every
// 500 ms: a few hundred bytes, never the 900 KB body.
func TestMetadataAsksForPartialObjectMetadata(t *testing.T) {
	f := &fakeAPI{resp: map[string]string{
		"GET /api/v1/namespaces/roid-k8s-applier/configmaps/roid-rbac-bundle": `{"kind":"PartialObjectMetadata","apiVersion":"meta.k8s.io/v1","metadata":{"name":"roid-rbac-bundle","resourceVersion":"4711"}}`,
	}, code: map[string]int{"GET /api/v1/namespaces/roid-k8s-applier/configmaps/roid-rbac-relay": 404}}
	c, _ := newClient(t, f)
	m, ok, err := c.Metadata(context.Background(), kobj.KindConfigMap, "roid-k8s-applier", "roid-rbac-bundle")
	if err != nil || !ok || m.ResourceVersion != "4711" {
		t.Fatalf("metadata %+v %v %v", m, ok, err)
	}
	if got := f.last(); !strings.Contains(got.Accept, "as=PartialObjectMetadata") || !strings.Contains(got.Accept, "application/json") {
		t.Fatalf("accept %q", got.Accept)
	}
	if _, ok, err := c.Metadata(context.Background(), kobj.KindConfigMap, "roid-k8s-applier", "roid-rbac-relay"); ok || err != nil {
		t.Fatalf("a missing object: ok=%v err=%v", ok, err)
	}
}

func TestMetadataRefusesAnAnswerWithoutAResourceVersion(t *testing.T) {
	f := &fakeAPI{resp: map[string]string{"GET /api/v1/namespaces/n/configmaps/x": `{"metadata":{"name":"x"}}`}}
	c, _ := newClient(t, f)
	if _, _, err := c.Metadata(context.Background(), kobj.KindConfigMap, "n", "x"); err == nil {
		t.Fatal("an answer without a resourceVersion was accepted: the watch loop would never see a change")
	}
}

func TestGetReturnsBinaryData(t *testing.T) {
	f := &fakeAPI{resp: map[string]string{"GET /api/v1/namespaces/n/configmaps/x": `{"metadata":{"name":"x","namespace":"n"},"binaryData":{"body.gz":"AQID"}}`}}
	c, _ := newClient(t, f)
	o, ok, err := c.Get(context.Background(), kobj.KindConfigMap, "n", "x")
	if err != nil || !ok || string(o.BinaryData["body.gz"]) != "\x01\x02\x03" {
		t.Fatalf("%+v %v %v", o, ok, err)
	}
}
