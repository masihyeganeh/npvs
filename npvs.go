package main

import (
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/chacha20poly1305"
)

const EnvelopeVersion1 = 1
const EnvelopeVersion5 = 5
const HeaderVersion = 1
const BodyMagic = "NPF"
const BodyVersion = 1
const KdfAppKey = "wbaes-ctr-sha256"
const KdfPass = "pbkdf2-hmac-sha256"

const (
	ConfigIDSize           = 16
	CreatorSize            = 33
	SaltSize               = 16
	RecipientPublicKeySize = 32
	RecipientWrapSize      = 93
	WrapSize               = 60
	NonceSize              = 12
	ContentIDSize          = 32
	SignatureSize          = 64
)

var MasterKey, _ = hex.DecodeString("81945737cc5197cb7ed46bf8d4d5e711c480133c6753e895db923236a937a13f")

type Method uint8

func (m Method) String() string {
	switch m {
	case MethodRecipient:
		return "Recipient"
	case MethodPass:
		return "Password"
	case MethodAppKey:
		return "AppKey"
	default:
		panic("unsupported case")
	}
}

const (
	MethodRecipient Method = iota
	MethodPass
	MethodAppKey
)

var Gen2AppKeyLabel = []byte("npvtunnel/appkey/v2 ")

const MetadataInfo = "NPVS-v5/metadata"

var FieldKeyInfo = []byte("NPV-fields-v1/field/")
var RecordAadInfo = []byte("NPV-fields-v1/record/")
var WbKdfPrefix = []byte("npvtunnel/appkey/v1 ")

type Recipient struct {
	PublicKey []byte
	Wrap      []byte
}

type Item struct {
	Seq   uint16
	Flags uint16
	Data  []byte
}

// NPVS holds what is common to all envelope versions plus the V5-only fields.
type NPVS struct {
	ConfigID         [ConfigIDSize]byte
	CreatorPublicKey [CreatorSize]byte
	Method           Method
	Recipients       []Recipient
	Metadata         []byte // V5

	Items []Item // V5
	Body  []byte // V1: decrypted body

	RemainingBody []byte
	Signature     [SignatureSize]byte
}

// readBodyHeader reads the nonce and body length that start the encrypted body.
func readBodyHeader(r *BytesReader) (nonce [NonceSize]byte, bodyLen uint32, err error) {
	b, err := r.readBytes(NonceSize)
	if err != nil {
		return nonce, 0, err
	}

	bodyLen, err = r.readLen(SignatureSize)
	return [NonceSize]byte(b), bodyLen, err
}

// readSignature reads the trailing signature.
func (n *NPVS) readSignature(r *BytesReader) error {
	signature, err := r.readBytes(SignatureSize)
	if err != nil {
		return err
	}
	n.Signature = [SignatureSize]byte(signature)
	return nil
}

func openAEAD(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// unwrapDEK opens a wrap (nonce || ciphertext) with the key-encryption key.
func unwrapDEK(kek []byte, salt [SaltSize]byte, wrap [WrapSize]byte) ([]byte, error) {
	return openAEAD(kek, wrap[:NonceSize], wrap[NonceSize:], salt[:])
}

// decodeFixed decodes unpadded base64url and checks the decoded size.
func decodeFixed(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, ErrMalformedPayload
	}
	return b, nil
}
