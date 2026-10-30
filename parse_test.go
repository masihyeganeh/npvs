package main

import (
	"errors"
	"os"
	"testing"
)

func parseFile(t *testing.T, path, password string) *File {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	f, err := Parse(b, password)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseNpvt(t *testing.T) {
	f := parseFile(t, "testdata/cfg.npvt", "")
	if f.Kind != KindNPVT || len(f.Payloads) == 0 {
		t.Fatalf("unexpected result: %+v", f)
	}
}

func TestParseNpvs1(t *testing.T) {
	for path, password := range map[string]string{
		"testdata/sample-appkey.npvs":     "",
		"testdata/sample-passphrase.npvs": "sirvdaram",
	} {
		t.Run(path, func(t *testing.T) {
			f := parseFile(t, path, password)
			if f.Version != EnvelopeVersion1 || len(f.NPVS.Body) == 0 {
				t.Fatalf("unexpected result: %+v", f)
			}
		})
	}
}

func TestParseNpvs5(t *testing.T) {
	f := parseFile(t, "testdata/sample-gen2.npvs", "")
	if f.Version != EnvelopeVersion5 || len(f.NPVS.Items) == 0 {
		t.Fatalf("unexpected result: %+v", f)
	}
}

func TestParseErrors(t *testing.T) {
	for in, want := range map[string]error{
		"XYZS\x01": ErrNotNPV,
		"NPVX\x01": ErrNotNPV,
		"NPVS\x09": ErrUnsupportedEnvelopeVersion,
	} {
		if _, err := Parse([]byte(in), ""); !errors.Is(err, want) {
			t.Errorf("Parse(%q) = %v, want %v", in, err, want)
		}
	}
}

func TestParseNpvs1PasswordRequired(t *testing.T) {
	b, err := os.ReadFile("testdata/sample-passphrase.npvs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b, ""); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("got %v, want %v", err, ErrPasswordRequired)
	}
}
