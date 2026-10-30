package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"regexp"
	"slices"
)

var sentinelPattern = regexp.MustCompile("npvs1:([^\\s\"']+)")

// parseV5 parses an envelope whose reader is positioned after the version byte.
func parseV5(r *BytesReader) (*NPVS, error) {
	res := &NPVS{}

	headerLen, err := r.readLen(0)
	if err != nil {
		return nil, err
	}

	headerStart := r.Mark()

	headerVersion, err := r.readByte()
	if err != nil {
		return nil, err
	}

	if headerVersion != HeaderVersion {
		return nil, ErrUnsupportedHeaderVersion
	}

	configID, err := r.readBytes(ConfigIDSize)
	if err != nil {
		return nil, err
	}
	res.ConfigID = [ConfigIDSize]byte(configID)

	creator, err := r.readBytes(CreatorSize)
	if err != nil {
		return nil, err
	}
	res.CreatorPublicKey = [CreatorSize]byte(creator)

	var salt [SaltSize]byte
	var wrap [WrapSize]byte

	method, err := r.readByte()
	if err != nil {
		return nil, err
	}

	switch Method(method) {
	case MethodRecipient:
		recipientsLen, err := r.readU16()
		if err != nil {
			return nil, err
		}

		if recipientsLen > 1024 {
			return nil, ErrTooManyRecipients
		}

		res.Recipients = make([]Recipient, 0, recipientsLen)

		for range recipientsLen {
			publicKey, err := r.readBytes(RecipientPublicKeySize)
			if err != nil {
				return nil, err
			}

			wrap, err := r.readBytes(RecipientWrapSize)
			if err != nil {
				return nil, err
			}

			res.Recipients = append(res.Recipients, Recipient{PublicKey: publicKey, Wrap: wrap})
		}

	case MethodPass, MethodAppKey:
		iterations, err := r.readU32()
		if err != nil {
			return nil, err
		}

		if Method(method) == MethodAppKey && iterations != uint32(MethodAppKey) {
			return nil, ErrMalformedPayload
		}

		saltBytes, err := r.readBytes(SaltSize)
		if err != nil {
			return nil, err
		}
		salt = [SaltSize]byte(saltBytes)

		wrapBytes, err := r.readBytes(WrapSize)
		if err != nil {
			return nil, err
		}
		wrap = [WrapSize]byte(wrapBytes)
	default:
		return nil, ErrUnsupportedMethod
	}
	res.Method = Method(method)

	// Everything read so far in the header is the AAD of the metadata.
	prefix := r.Since(headerStart)

	metaLen, err := r.readLen(0)
	if err != nil {
		return nil, err
	}

	if uint64(len(prefix))+uint64(metaLen) > uint64(headerLen) {
		return nil, ErrMalformedPayload
	}

	metaBlob, err := r.readBytes(metaLen)
	if err != nil {
		return nil, err
	}

	nonce, _, err := readBodyHeader(r)
	if err != nil {
		return nil, err
	}

	magic, err := r.readBytes(uint32(len(BodyMagic)))
	if err != nil {
		return nil, err
	}

	if string(magic) != BodyMagic {
		return nil, ErrMalformedPayload
	}

	bodyVersion, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if bodyVersion != BodyVersion {
		return nil, ErrUnsupportedBodyVersion
	}

	contentIDBytes, err := r.readBytes(ContentIDSize)
	if err != nil {
		return nil, err
	}

	contentID := [ContentIDSize]byte(contentIDBytes)

	kek, err := DeriveV5Key(salt, res.ConfigID)
	if err != nil {
		return nil, err
	}

	dek, err := unwrapDEK(kek, salt, wrap)
	if err != nil {
		return nil, err
	}

	metaKey, err := hkdf.Key(sha256.New, dek, nonce[:], MetadataInfo, 32)
	if err != nil {
		return nil, err
	}

	res.Metadata, err = openAEAD(metaKey, nonce[:], metaBlob, prefix)
	if err != nil {
		return nil, err
	}

	if err = res.readItems(r, dek, contentID); err != nil {
		return nil, err
	}

	remainingBodyLen := r.Remaining() - SignatureSize

	if remainingBodyLen < 0 {
		return nil, ErrMalformedPayload
	}

	if remainingBodyLen > 0 {
		res.RemainingBody, err = r.readBytes(uint32(remainingBodyLen))
		if err != nil {
			return nil, err
		}
	}

	if err = res.readSignature(r); err != nil {
		return nil, err
	}

	return res, nil
}

func (n *NPVS) readItems(r *BytesReader, dek []byte, contentID [ContentIDSize]byte) error {
	count, err := r.readU16()
	if err != nil {
		return err
	}

	n.Items = make([]Item, 0, count)

	for range count {
		seq, err := r.readU16()
		if err != nil {
			return err
		}

		flags, err := r.readU16()
		if err != nil {
			return err
		}

		blobLen, err := r.readU16()
		if err != nil {
			return err
		}

		blob, err := r.readBytes(uint32(blobLen))
		if err != nil {
			return err
		}

		ptLen := len(blob) - 16
		if ptLen < 0 {
			continue
		}
		seqBytes := binary.BigEndian.AppendUint16(nil, seq)
		info := slices.Concat(FieldKeyInfo, seqBytes)
		key, err := hkdf.Key(sha256.New, dek, contentID[:], string(info), 32)
		if err != nil {
			return err
		}

		aad := slices.Concat(RecordAadInfo, contentID[:], seqBytes, binary.BigEndian.AppendUint32(nil, uint32(ptLen)))

		pt, err := openAEAD(key, make([]byte, NonceSize), blob, aad)
		if err != nil {
			return err
		}

		pt = sentinelPattern.ReplaceAllFunc(pt, func(s []byte) []byte {
			txt, err := base64.StdEncoding.DecodeString(string(s[6:]))
			if err != nil {
				return s
			}
			return txt
		})

		pt = bytes.Trim(pt, "\"'")

		n.Items = append(n.Items, Item{Seq: seq, Flags: flags, Data: pt})
	}

	return nil
}

func encrypt(plaintext [SaltSize]byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	c, err := aes.NewCipher(MasterKey)
	if err != nil {
		return nil, err
	}
	c.Encrypt(ciphertext, plaintext[:])
	return ciphertext, nil
}

func DeriveV5Key(salt [SaltSize]byte, configID [ConfigIDSize]byte) ([]byte, error) {
	encryptedSalt, err := encrypt(salt)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(Gen2AppKeyLabel)
	h.Write(encryptedSalt)
	h.Write(configID[:])
	return h.Sum(nil), nil
}
