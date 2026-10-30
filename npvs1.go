package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"time"
)

type Creator struct {
	Fp string `json:"fp"`
	Pk string `json:"pk"`
}

type Policy struct {
	DisplayMessage string     `json:"displayMessage"`
	ConfigVersion  int        `json:"configVersion"`
	ExpiresAt      *time.Time `json:"expiresAt"`
}

type AppKey struct {
	Kdf   string `json:"kdf"`
	KeyId int    `json:"keyId"`
	Salt  string `json:"salt"`
	Wrap  string `json:"wrap"`
}

type Passphrase struct {
	Iters int    `json:"iters"`
	Kdf   string `json:"kdf"`
	Salt  string `json:"salt"`
	Wrap  string `json:"wrap"`
}

type Header struct {
	Version    int         `json:"v"`
	ConfigID   string      `json:"configId"`
	IssuedAt   time.Time   `json:"issuedAt"`
	Creator    Creator     `json:"creator"`
	Policy     Policy      `json:"policy"`
	AppKey     *AppKey     `json:"appKey"`
	Passphrase *Passphrase `json:"passphrase"`
}

// parseV1 parses an envelope whose reader is positioned after the version byte.
func parseV1(r *BytesReader, password string) (*NPVS, error) {
	res := &NPVS{}

	headerLen, err := r.readLen(0)
	if err != nil {
		return nil, err
	}

	headerRaw, err := r.readBytes(headerLen)
	if err != nil {
		return nil, err
	}

	var header Header
	if err = json.Unmarshal(headerRaw, &header); err != nil {
		return nil, err
	}

	if header.Version != HeaderVersion {
		return nil, ErrUnsupportedHeaderVersion
	}

	dek, err := res.unwrapV1(&header, password)
	if err != nil {
		return nil, err
	}

	nonce, bodyLen, err := readBodyHeader(r)
	if err != nil {
		return nil, err
	}

	body, err := r.readBytes(bodyLen)
	if err != nil {
		return nil, err
	}

	if err = res.readSignature(r); err != nil {
		return nil, err
	}

	res.Body, err = openAEAD(dek, nonce[:], body, headerRaw)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// unwrapV1 sets the method of n from the header and returns the DEK.
func (n *NPVS) unwrapV1(h *Header, password string) ([]byte, error) {
	switch {
	case h.AppKey != nil:
		if h.AppKey.Kdf != KdfAppKey {
			return nil, ErrUnsupportedKdf
		}
		if h.AppKey.KeyId != 1 {
			return nil, ErrUnsupportedKeyID
		}
		salt, wrap, err := decodeSaltWrap(h.AppKey.Salt, h.AppKey.Wrap)
		if err != nil {
			return nil, err
		}
		n.Method = MethodAppKey

		for _, kek := range DeriveV1Keys(salt) {
			var dek []byte
			if dek, err = unwrapDEK(kek, salt, wrap); err == nil {
				return dek, nil
			}
		}
		return nil, err

	case h.Passphrase != nil:
		if h.Passphrase.Kdf != KdfPass {
			return nil, ErrUnsupportedKdf
		}
		if password == "" {
			return nil, ErrPasswordRequired
		}
		if h.Passphrase.Iters <= 0 {
			return nil, ErrMalformedPayload
		}
		salt, wrap, err := decodeSaltWrap(h.Passphrase.Salt, h.Passphrase.Wrap)
		if err != nil {
			return nil, err
		}
		n.Method = MethodPass

		kek, err := pbkdf2.Key(sha256.New, password, salt[:], h.Passphrase.Iters, 32)
		if err != nil {
			return nil, err
		}
		return unwrapDEK(kek, salt, wrap)
	}

	return nil, ErrRecipientWithPrivateKeyNotImplemented
}

func decodeSaltWrap(salt, wrap string) (s [SaltSize]byte, w [WrapSize]byte, err error) {
	sb, err := decodeFixed(salt, SaltSize)
	if err != nil {
		return s, w, err
	}
	wb, err := decodeFixed(wrap, WrapSize)
	if err != nil {
		return s, w, err
	}
	return [SaltSize]byte(sb), [WrapSize]byte(wb), nil
}

// DeriveV1Keys returns the candidate key-encryption keys, one per white-box generation.
func DeriveV1Keys(salt [SaltSize]byte) [2][]byte {
	var keys [2][]byte
	for i := range keys {
		block := core(salt, tlast[i])
		h := sha256.New()
		h.Write(WbKdfPrefix)
		h.Write(block[:])
		keys[i] = h.Sum(nil)
	}
	return keys
}
