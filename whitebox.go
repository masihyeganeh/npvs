package main

import "encoding/base64"

// Table-free implementation of the npv white-box cipher.
//
// A 2-round substitution-permutation network used as the core of AES-CTR.
//
// It is a customization of AES. It borrows two AES pieces only:
//   - the AES S-box            [AES]
//   - the AES ShiftRows order  [AES]
//
// The mixing layer is a bespoke per-column 32x32 GF(2) map (NOT MixColumns),
// and there are only 2 rounds.
//
// Self-test: core(00 01 02 ... 0f) == 58bf2ecbd052f9cdb4704ac2b7fda375

// sbox is the standard AES (Rijndael) S-box.
// can be found in Golang's src/crypto/internal/fips140/aes/const.go as sbox0.
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// [AES] standard AES ShiftRows byte permutation
var shiftOrder = [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}

// round keys (16 bytes each)
var k0 = [16]byte{0xd4, 0x6b, 0x21, 0x8c, 0xbe, 0x34, 0xc8, 0xaa, 0xaa, 0xfa, 0x5d, 0x4a, 0xc1, 0xf4, 0x5a, 0xb7}
var k1 = [16]byte{0xaa, 0xb9, 0xf0, 0x43, 0x14, 0xdc, 0x38, 0xe9, 0xbe, 0x26, 0x8b, 0xa3, 0x7f, 0xd2, 0xd1, 0xcf}
var k2 = [16]byte{0xfe, 0xdb, 0x81, 0x1d, 0xea, 0xfd, 0x50, 0x5e, 0x54, 0x2f, 0xa0, 0xb7, 0x2b, 0x96, 0x98, 0x14}

// [NOT AES] custom linear mixing layer.
// mix[c] is a 32x32 GF(2) matrix for column c, stored as the 32 images of the
// input bits (input byte 0 occupies the most-significant 8 bits). This stands
// in for what AES MixColumns would be, but it is bespoke and differs per column.
var mix = [4][32]uint32{
	{0xc1a35b69, 0xe834e3b4, 0x72aed1f9, 0xcc13c6f3, 0x10a20702, 0x05a47f66, 0xff70858a, 0xca26e3c5, 0xc1a35b69, 0xe834e3b4, 0x72aed1f9, 0xcc13c6f3, 0x10a20702, 0x05a47f66, 0xff70858a, 0xca26e3c5, 0xc1a35b69, 0xe834e3b4, 0x72aed1f9, 0xcc13c6f3, 0x10a20702, 0x05a47f66, 0xff70858a, 0xca26e3c5, 0xc1a35b69, 0xe834e3b4, 0x72aed1f9, 0xcc13c6f3, 0x10a20702, 0x05a47f66, 0xff70858a, 0xca26e3c5},
	{0xc071d765, 0x7c6e59f2, 0x625cc067, 0x17047376, 0x6f28c144, 0xba06ead6, 0x7b55a790, 0x1559a81a, 0xc071d765, 0x7c6e59f2, 0x625cc067, 0x17047376, 0x6f28c144, 0xba06ead6, 0x7b55a790, 0x1559a81a, 0xc071d765, 0x7c6e59f2, 0x625cc067, 0x17047376, 0x6f28c144, 0xba06ead6, 0x7b55a790, 0x1559a81a, 0xc071d765, 0x7c6e59f2, 0x625cc067, 0x17047376, 0x6f28c144, 0xba06ead6, 0x7b55a790, 0x1559a81a},
	{0x7088767a, 0x315b8f10, 0xba4f3425, 0x1e3d907b, 0x66b163c9, 0x53890feb, 0x3b347002, 0x8195b5e4, 0x7088767a, 0x315b8f10, 0xba4f3425, 0x1e3d907b, 0x66b163c9, 0x53890feb, 0x3b347002, 0x8195b5e4, 0x7088767a, 0x315b8f10, 0xba4f3425, 0x1e3d907b, 0x66b163c9, 0x53890feb, 0x3b347002, 0x8195b5e4, 0x7088767a, 0x315b8f10, 0xba4f3425, 0x1e3d907b, 0x66b163c9, 0x53890feb, 0x3b347002, 0x8195b5e4},
	{0x92a16564, 0x0860463b, 0x854c4204, 0x817172c1, 0x14eff0a2, 0xed237113, 0x17836853, 0x0f6a2a64, 0x92a16564, 0x0860463b, 0x854c4204, 0x817172c1, 0x14eff0a2, 0xed237113, 0x17836853, 0x0f6a2a64, 0x92a16564, 0x0860463b, 0x854c4204, 0x817172c1, 0x14eff0a2, 0xed237113, 0x17836853, 0x0f6a2a64, 0x92a16564, 0x0860463b, 0x854c4204, 0x817172c1, 0x14eff0a2, 0xed237113, 0x17836853, 0x0f6a2a64},
}

// mixCol applies one column's 32x32 GF(2) linear map to 4 bytes.
func mixCol(col [4]byte, img [32]uint32) [4]byte {
	x := uint32(col[0])<<24 | uint32(col[1])<<16 | uint32(col[2])<<8 | uint32(col[3])
	var w uint32
	for bit := range 32 {
		if (x>>(31-bit))&1 == 1 {
			w ^= img[bit]
		}
	}
	return [4]byte{byte(w >> 24), byte(w >> 16), byte(w >> 8), byte(w)}
}

func shiftRows(st [16]byte) [16]byte {
	var out [16]byte
	for i := range 16 {
		out[i] = st[shiftOrder[i]]
	}
	return out
}

// coreV2Only transforms one 16-byte block (the CTR counter) into the keystream block.
// This is not used anymore, but if we decide to keep v2 only, this is a better implementation.
// Let's keep it.
func coreV2Only(block [16]byte) [16]byte {
	st := block

	// round 1
	for i := range 16 { // [AES] AddRoundKey K0
		st[i] ^= k0[i]
	}
	st = shiftRows(st)  // [AES] ShiftRows
	for i := range 16 { // [AES] SubBytes
		st[i] = sbox[st[i]]
	}
	for j := range 4 { // [NOT AES] custom mixing layer
		var col [4]byte
		copy(col[:], st[4*j:4*j+4])
		m := mixCol(col, mix[j])
		copy(st[4*j:4*j+4], m[:])
	}

	// round 2 (final)
	for i := range 16 { // [AES] AddRoundKey K1
		st[i] ^= k1[i]
	}
	st = shiftRows(st)  // [AES] ShiftRows
	for i := range 16 { // [AES] SubBytes
		st[i] = sbox[st[i]]
	}
	for i := range 16 { // [AES] AddRoundKey K2
		st[i] ^= k2[i]
	}
	return st
}

// core runs the white-box cipher on one 16-byte block for one final table.
func core(block [16]byte, tl []byte) [16]byte {
	st := block
	for i := range 16 { // [AES] AddRoundKey K0
		st[i] ^= k0[i]
	}
	st = shiftRows(st)  // [AES] ShiftRows
	for i := range 16 { // [AES] SubBytes
		st[i] = sbox[st[i]]
	}
	for j := range 4 { // [NOT AES] custom mixing layer
		var col [4]byte
		copy(col[:], st[4*j:4*j+4])
		m := mixCol(col, mix[j])
		copy(st[4*j:4*j+4], m[:])
	}
	st = shiftRows(st) // [AES] final ShiftRows
	var out [16]byte
	for i := range 16 { // final round (generation-specific table)
		out[i] = tl[i*256+int(st[i])]
	}
	return out
}

// ctr runs CTR mode with a 16-byte big-endian counter starting at nonce.
func ctr(nonce, data []byte) []byte {
	var counter [16]byte
	copy(counter[:], nonce)
	out := make([]byte, len(data))
	for off := 0; off < len(data); off += 16 {
		ks := core(counter, tlast[1])
		for i := 15; i >= 0; i-- { // big-endian increment
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
		n := min(len(data)-off, 16)
		for i := range n {
			out[off+i] = data[off+i] ^ ks[i]
		}
	}
	return out
}

// DecryptBlob decrypts a payload whose first 16 bytes are the nonce/IV and whose
// remainder is the CTR ciphertext.
func DecryptBlob(data []byte) []byte {
	if len(data) <= 16 {
		return []byte{}
	}
	return ctr(data[:16], data[16:])
}

// Generation-specific final tables (16 x 256 bytes): the final round baked in.
// v2 = AES S-box + round keys (bijective); v1 = non-bijective finalization.
var tlast = [2][]byte{mustB64(tlastV1B64), mustB64(tlastV2B64)}

const tlastV1B64 = "" +
	"Upw8LRqHb2vE9B7M2qK3+AoUkqhQ9puEyZMZNrBXcyuAwzpZ542ao+0SM/K66aFpRuq4EPUlIKCx" +
	"Ip5/bnbc1HkXZeDWITCrZu8fBnBqlyfT8b9nRehOAHfzcl+8lkEYiuEWI3V0tUPb0ESGSjjiWABH" +
	"n8vjYHg/S5iOwAjwtv0bD8pbz+uPJgDYSQMJMsjBfhz57EyLFdndPfo5+wDmaJnVzv9ViAApiYWd" +
	"gpE7DJVcUVMqjD5iWjeDNHy5DgSn/IG7B2FWrsJUBS4RzXu9ACTfQkgNLO4BvnGvXcYLbGMoTazF" +
	"0XrXHdLk932kXuWQQMeUNaYxtLL+E60vT6XeAl0axkW67oxik9gt1avlbr2QZlBRMwavxMd9bx1h" +
	"o/71a49gzZpC9tQAPZkAV3pS1hWO8wRAxVwysgJVTzojQ8oFhdAAnTVjz/nxS1O7WpQHv4bCqB98" +
	"peaETJ/MFtfIN76hddO3jS8xVg6VcjwT7LZKTj+iGQh3uZLd/4c76eHRkZeDFLEQZeL7J2qAiArb" +
	"NvI49F+J4A1owLWBe9JY98HLJCgJZwAB+klG4y6KeJtUi+dEc54i2aSYluheCzRxIEd/ABt2D3l0" +
	"IYKcKxFZEqYlDHCt69q88CmwtB64p6ygMPxprtzJWznDTd5B3xz4GAAD6s7vfj4q7eQsF2wmSP28" +
	"/yZF8pjc5QCSjUyWxRbelTlvx1qK319dzgDhCRGro+MtUkP4ZRQQi7sAYd2lh8hrddftiS/75Oy2" +
	"SWYoz1QMnvVcaQsKPMqvpPk7RzUnnTjWtOAfnEAH5zS/8Y93gsloBp8aXgDUT5AZeWAVD1jojqwY" +
	"wJc61TGMCCAN6cNnPgDmgLH3KlZ/+vb94kTu6nMuI1UsQfMlHfxIA0txxth7cAAktZSwWfCnEnw2" +
	"TXa+t2MBk4b0M6ZqQqJGhRuEF5kyV7rTBa5iqJutAogh2++auD9K607ZzctsgVDS2jB9of6DeMQp" +
	"Hr3ReituUQSyzMKgWzc9U3J+kQ7BItB0uRwTl5agVgJpwPXbALsBMzhlp4MA3JukSih8E+seVXuo" +
	"IwDCNUjT9JoDhomTxHQMheX8C6ZJrRIwhFx1X/uiEJS8kW4EQHkgY7rZClmKQvEOEdDGFkPDCaXz" +
	"W5WNNz/BUpx9APmIjH+xzt9BORtUFycv/RUAZ3j36UtxtFPIkHAq1fqZMv40rssmT71HcwYHMZ4U" +
	"0kVRVySj1ndGrOE98B3MTrWCIU1iH+RYmC5QXua38s3P7uINPMeroeglgI+SXb5Ma7bK4zZ6HC3Y" +
	"cnbvZmphft1vuYGyv8mw7VpE52DUn9cILMVs7Pi4KdHqIis7juAAaK869v+dDxqHGIsF3j7aGRAA" +
	"rRogaCOXdk6YKkc+SEUYgYUviZadkRQ9QZza643B8nzvcO4tySkBzVif7fhqCNzVHSZdF3nMmzLb" +
	"/95PDxvKFluxuTvqB6CmsiWAIVTT8YSwSuNpxvDDCcVuuNE8WXh30h+7SQBl+hUZOFZcMMsAp9lv" +
	"OgVAEbrWdUKvE+iVyMB6YoprpTY0tOExrARS/rV9rv0n5vkGjrfzmS5NlNdnP6RDDSLdh4+QROKG" +
	"vB4Ao+zOtgrY0OB7fw6TKDlGiKLpHOSa1F+MbCv3dIvfvVP2TF4sUJLPxKFXYWACN571VQyogmZL" +
	"Y+davlH8q3PH5YMzAH4LEnL7JL/CNXH0AAMKMcvCbttKAMzojCUYDMlY+Gfla94++TpPiBbafR/6" +
	"75I4D5aKhp6BVosDKprWzfy6DQekNIA3f489YVlfUlApzni+sFcGLRJiVa3B/4K4BMUIb2C9cqxe" +
	"Di/tAifcQUunXeaT0ef0ftJ51B4rTq/GTKbdAf0QriylMrexQ8SXNtmhtPvH9x3PGYRsaFGfPy4A" +
	"VHAoypAaNVP1mIcJF5Grueqiau4RMPHkjpmgg8A5WgB139eyIZ189iYjo0XpuxNzaZQkZewcBdUi" +
	"M6h6FGbjv5VCG3TwcVxG600A0PK8AEk74VvY00eFdne2QIniFSAL87X+SJuNw+BjezwARJzIbiA2" +
	"5VMYXqZlMekHkdbOTSjqfnX2TJbkjbhPJO0b2tvx3F3Ztu84EskRX30E4EbrqLFByIk5xN5Oy7nX" +
	"BZ6PeNEwjB96ctjAvhZE6A6Oi1tcnbxDxw9HFPeUAC4NNCNJmLc9Z4Xd+R4GPLqkKjVY/mKwWmpW" +
	"GQx0g5Iy/MXBKbSBA71QrHAL4Zs6ae4cGp8I01lKfD5L8AprAuOGAHnUf/MB3xDNwqVo5uxxiq9A" +
	"gqO/gKv6HRPVYwAVL1JsAPjP0potmQkAoBeE/f/y9MyQIiwzKyc7opU/UWB7N4euJvuXVJNzxkjK" +
	"VUJXstB3uyXired2w29mnKf1AKG1iCFFYURy3Vf+BDBF7YhlDNpxvXcAXo8NBe+ifmfglTSRBhIU" +
	"pfSxjtsAEx0hXKcb9sFiDtEe/Q+rZsPMf4To4oytoU4lKSI9mzE1rHU5X24o9YmgI5fclK4ZB6Tx" +
	"/Irzniz6wnjNo+mSAGFor7v7aktvhi+dfZlaxFvIRrzeTFkr7Hm1cHsm5Jjq+EJBKoO21NXjFTjr" +
	"YC5QqF0W5wlrP8BDn9hPxqa/ytCHN7fZQMWBdguQU9f/0jYcuOFRc8cfSOUK7rJNUpNJGskBYyD5" +
	"mi1HAzqCEd8+1s50fErmsBiFVQCAVABsvgJ6WBc88o2cJ7rLzzNplrn3EIvTtAAIMlbwJDv6XDEu" +
	"oL44Ahr92YFjOQCcsC3Fwfg2lodwCB1Sbl60Zl+PigrsQBK6xNx2fhuINNVNJzAJKmmQ8xBDC8NH" +
	"uJlY70LkAHlbFc0WPOuy3VnY9XyLmgHTvc9K2sA9jcxFtaxJytKVA+01YaJaHFfhMiRq394f6SBL" +
	"vIngkkjycXruLOYhv3PUtlNGUc5MwneXUJNlQSWMsaVg8aOYYmvHcuMAJpTI8Pb7+YATpK4NnSme" +
	"1v8iAIMzfwBVO5GmPyMvNyinhkSrjnXo4myhxskU2wX3y/wEaFYrEa1n0RcZ/q+EuwybHhjqAD6f" +
	"5Q90qFS5B4V70H23gucGbw70Tzp4Tl3XmklfEdkhZyx4lk4aMrEA7goBlVeb6TOJWzDH8qSlAJKm" +
	"IqOOAEeQyQIgbraUOZ97tz7O16G7RvaoxrQxB/DhemDzT66/pw0FlztpwST08XE8w+IjazhwuFES" +
	"64g2XEtyGELI52GGovrbxUN5gSdKVRUlzx0Lc2Ypg03t/MtWvrovwnz+nnQP05EWReR34GVjAzUm" +
	"rHWPNEH5nH0UAKsGzG+gfowX2r2y9Q6Tmdz9P9CF1P/AHABsYi1Qatawh38T5lLlrWjf1XaNgIL7" +
	"Xe8Ai1hUTFNA6t1ESAQfLoRZ0fgM7CvoKrU3ua/NKD2dWsQIvAmY0tjjGRDK3huKHjpe9ywBKa0f" +
	"RuLI4TmNrxD0G7ZBWDixyXkuNDu+J0lu9Yh/0J4VxuijVq7BlfcZJmG9PhrYhY68BhRmSH3Uv+sd" +
	"KypHaJfNLXXuCcz2VErF2g6oQJKaAOmmhPxicwzCMTVE2cAh73yCijAo5k4YtH7+q3sArABM/zfk" +
	"twAH3p3E/bnT8QPgLzI9mFUcFnqBsF9TcnBPClvj7ZMl5Vmi3/CcPwjzcaBNgFwR+8prHpnq7Phv" +
	"ACOMurvO+gDym3YTiUOPJKRng2O4NqU6p7IgQkuHEtUXXTOGlp9XbJQFRVHReJG1aiJp3Vr551AN" +
	"dAIPPATSYMPc19tSy89lkKHHi153C9YALF4w4nlon09Wpi9u3iM5Lva4muMHoQwWO7o+UQjf9Wpf" +
	"qMMK/D08zw2ZkhGrcQOC1g7gdjEpAInH0QK0/7lBAHXVGyImzlOFV72Nsf7rk+HbXUPN0r8Zf1Da" +
	"gGI6HvkQc4rJ6tPErrt6W6Qg6KDzWfGjD+lpbLw212v4nZU/J07yyLWL5x8oWGdMHfr0MoQBC5YA" +
	"SKdlRBTmOPcqJUKPjOUEYVSeM5g0vq2b2awX7Xzdjgn7/XjvZuRat0uX7AYSg0ZSb8aihkoAkSSI" +
	"gXtApbBVN5BcwgVwAHSUIa8tsraHnNBgScEcy9TMwNxFcthjGhgVEyt3xTV9yn7uTUfw+djUOwrx" +
	"nZfeE7a5pGuIeoO0F3tUKdJurhhmaNCBxPvkc2dhEpXgQXCa1wvGK/p4rwTIApj9EHmLcUUwMQeo" +
	"Il6ZDMDJqzkssS69M+gI7C8+GvNa2s6OH+fcFB0NuNac61mPt4SJ/4bbbHLRVuIA4V2A/NUATCob" +
	"7kRA2VBcV0g9kH+bJAayakNpzZQmooqn9AN+5cKsNbC/pfJCOgDTyrU26q2SfB5KJd0oY02eFVuh" +
	"oJZgNF/2w+2fjTcFDlORI4VRTsHffUeCZf6mRhzjzFLPvrpJh/jpdw8tYiERGcvwIHX1P5PFAKO7" +
	"AQn3AABLWDJ2TxZVjO88b7x0xzgn5sD6fGLs8544XnH7oUMbP9hFVPQ6AwfvcqR2nKyQ38qyeNCC" +
	"LshITZ0X9krZvLQeBjFSq+jL8uWPmlt6hQHJgdIP15m7wiaALTcamx9wKf7UiA1/EcNYSb5ud4cO" +
	"T/8CGKP3L8FXEAiLqObwI5XemGBLfoniK90cHe4suAAwilAihJF0FrF94yRRklW1AI4MkzOiZ3NO" +
	"54OnayGwBQCgWmFCOzk0MgpW5BRc61/PbGbRl6a98UFo4D3q9e3h/QBT+SAqt0xphkRlNccZ1gsE" +
	"Y65v0+mUAMY+CXlGADzb1ROlXfyvKNrcWc5HxXuWarbNJ63EJUB1vxK5FZ+MuviNNsyfihh6c78q" +
	"7Zxfu1uADp0CrD19aelAAI0vZQu+rqdvVDVMOjcEPOpYUhpR5WLB32iomf8AZk8z7vvk7+Nq8/dd" +
	"JC5CuYhna0rJO9gXCgWgAN1hmufIpAcwSHcyY9vVqx3yUyah0tTAV8tJmHW4ACnDyqNOK7F7txyR" +
	"G7SCg/bCOPTObHL94jaQf1Cv9RVN1jFaSzT6CQ184XgAopLRnrzE3nYgjEbGk0P4GddEurIIEFw/" +
	"5qX8xYHrVZSLdMcP3I/ZAbWXKMwjjhQ5EZUnftrwA4YfcVbNsEd5YACJ8UEWDPmtzyEeWYUG6KYt" +
	"/tCbbpZwReyH0yUTEiLgvbaEPixeHi4m9EgwEl12uMfWAPCBhXkj3PO9WsGZ/uBCeBy6bnH4BxjZ" +
	"A1CDSylqANBnDUlwyFuVdJyEPjYArPpSzx9KygWM7PWAms19/ZMKj8s8QdoZnbWYfFbyqxs5jVUC" +
	"r0CkOjFsrtKgsggLYMn8np8AX3KhKgAa4hdcrUMhdYoJ1ZIyh+mj2OMrIuXxsSABJcxl1zfTEI4R" +
	"ggz2lAYTYaYz/29jaHfRe3/mP3MVJGK/w+pp3Zbe5FNN7ru2wLnUZrCI7777xJEnWVdrFu1RvIso" +
	"RJtUt0XhLImGNc6iqMbn6wQOOJcdtE56D6fCL0aQO/c9+RTFR0+l6DQtAN9+20xYXg=="
const tlastV2B64 = "" +
	"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"

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
