package main

import (
	"bytes"
	"encoding/base64"
)

// parseNpvt decrypts every blob of a (possibly concatenated) npvt file.
func parseNpvt(b []byte) ([][]byte, error) {
	b = bytes.ReplaceAll(b, []byte("NPVTSUB1"), []byte(","))
	b = bytes.ReplaceAll(b, []byte("NPVT1"), []byte(","))

	var payloads [][]byte
	for part := range bytes.SplitSeq(b, []byte(",")) {
		part = bytes.TrimSpace(part)
		if len(part) == 0 {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(string(part))
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, DecryptBlob(blob))
	}
	return payloads, nil
}
