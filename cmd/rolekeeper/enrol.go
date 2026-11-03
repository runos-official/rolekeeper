package main

import (
	"context"
	"crypto/tls"
	"log"
)

// enrol is the pull transport's certificate enrolment. That transport is not
// part of this build: rolekeeper runs on the relay transport only.
func enrol(ctx context.Context, url, caFile, tokenFile, cluster string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	log.Fatal("rolekeeper: the pull transport is not part of this build; set ROID_K8S_TRANSPORT=relay")
	return nil
}
