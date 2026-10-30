package main

// Magic is the first 3 bytes of every file. The 4th byte selects the Kind,
// and for NPVS the 5th byte is the envelope version.
const Magic = "NPV"

type Kind byte

const (
	KindNPVS Kind = 'S'
	KindNPVT Kind = 'T'
)

type File struct {
	Kind    Kind
	Version int // envelope version, NPVS only

	NPVS     *NPVS    // KindNPVS
	Payloads [][]byte // KindNPVT: decrypted blobs
}

// Parse decodes b. The password is only needed for passphrase-protected files.
func Parse(b []byte, password string) (*File, error) {
	r := NewBytesReader(b)

	magic, err := r.readBytes(uint32(len(Magic)))
	if err != nil {
		return nil, err
	}
	if string(magic) != Magic {
		return nil, ErrNotNPV
	}

	kind, err := r.readByte()
	if err != nil {
		return nil, err
	}

	switch Kind(kind) {
	case KindNPVT:
		payloads, err := parseNpvt(b)
		if err != nil {
			return nil, err
		}
		return &File{Kind: KindNPVT, Payloads: payloads}, nil

	case KindNPVS:
		version, err := r.readByte()
		if err != nil {
			return nil, err
		}

		var npvs *NPVS
		switch version {
		case EnvelopeVersion1:
			npvs, err = parseV1(r, password)
		case EnvelopeVersion5:
			npvs, err = parseV5(r)
		default:
			return nil, ErrUnsupportedEnvelopeVersion
		}
		if err != nil {
			return nil, err
		}
		return &File{Kind: KindNPVS, Version: int(version), NPVS: npvs}, nil
	}

	return nil, ErrNotNPV
}
