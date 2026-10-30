package main

import (
	"bytes"
	"encoding/binary"
	"io"
)

type BytesReader struct {
	b []byte
	r *bytes.Reader
}

func NewBytesReader(b []byte) *BytesReader {
	return &BytesReader{b: b, r: bytes.NewReader(b)}
}

func (b BytesReader) readByte() (byte, error) {
	if b.r.Len() < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	return b.r.ReadByte()
}

func (b BytesReader) readU16() (uint16, error) {
	if b.r.Len() < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	var buf [2]byte
	if _, err := io.ReadFull(b.r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

func (b BytesReader) readU32() (uint32, error) {
	if b.r.Len() < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	var buf [4]byte
	if _, err := io.ReadFull(b.r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

func (b BytesReader) readBytes(n uint32) ([]byte, error) {
	if uint64(n) > uint64(b.r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(b.r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// readLen reads an u32 length and checks that at least that many bytes,
// plus reserve trailing bytes, remain.
func (b BytesReader) readLen(reserve int) (uint32, error) {
	n, err := b.readU32()
	if err != nil {
		return 0, err
	}
	if uint64(n)+uint64(reserve) > uint64(b.r.Len()) {
		return 0, ErrMalformedPayload
	}
	return n, nil
}

func (b BytesReader) Remaining() int {
	return b.r.Len()
}

// Mark returns the current offset, to be passed to Since later.
func (b BytesReader) Mark() int {
	return len(b.b) - b.r.Len()
}

// Since returns the bytes consumed after the given mark.
func (b BytesReader) Since(mark int) []byte {
	return b.b[mark:b.Mark()]
}
