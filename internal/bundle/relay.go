package bundle

// The bundle in a ConfigMap: the JWT as roid signed it,
// plus the gzip of the raw body. Splitting the envelope is lossless: the
// signature covers the body bytes and the token id is their SHA-256.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Size limits of the relay.
const (
	// MaxGzBytes is the hard stop on the compressed body in the ConfigMap.
	// Roid's own rule is lower; the margin absorbs library differences.
	MaxGzBytes = 900_000
	// MaxBodyBytes is the applier's cap on the decompressed body.
	MaxBodyBytes = 16 << 20
)

// ErrTooLarge means the compressed or the decompressed body is above its
// limit.
var ErrTooLarge = errors.New("bundle: too_large")

// GzipBody compresses a body at level 6, the level the size rule counts.
func GzipBody(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, 6)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(body); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GunzipBody reads exactly one gzip member. It refuses a compressed input
// above MaxGzBytes, more than MaxBodyBytes of output, a second member and
// any byte after the first (Go reads concatenated members by default).
func GunzipBody(gz []byte) ([]byte, error) {
	if len(gz) > MaxGzBytes {
		return nil, fmt.Errorf("%w: body.gz is %d bytes, the limit is %d", ErrTooLarge, len(gz), MaxGzBytes)
	}
	src := bytes.NewReader(gz)
	zr, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("%w: body.gz: %v", ErrFormat, err)
	}
	zr.Multistream(false)
	out, err := io.ReadAll(io.LimitReader(zr, MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: body.gz: %v", ErrFormat, err)
	}
	if len(out) > MaxBodyBytes {
		return nil, fmt.Errorf("%w: the body is above %d bytes", ErrTooLarge, MaxBodyBytes)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: body.gz is empty", ErrFormat)
	}
	// The limit reader may stop before the member's end; read it out so the
	// trailer (CRC and size) is checked and the position is the member's end.
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return nil, fmt.Errorf("%w: body.gz: %v", ErrFormat, err)
	}
	if src.Len() != 0 {
		return nil, fmt.Errorf("%w: body.gz has %d bytes after its first member", ErrFormat, src.Len())
	}
	return out, nil
}

// RebuildEnvelope joins the token and the compressed body into the envelope
// bytes roid served, ready for Verifier.Verify.
func RebuildEnvelope(tok string, gz []byte) ([]byte, error) {
	body, err := GunzipBody(gz)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Bundle: tok, Body: body})
}
