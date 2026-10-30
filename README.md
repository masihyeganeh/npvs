# npvs

A parser for Napster VPN config files (`.npvt` and `.npvs`), written in Go.

It reads a file, decrypts it and prints the plaintext config (JSON or share links).

## Usage

```sh
go run . [-password <password>] <file>
```

```sh
go run . testdata/cfg.npvt
go run . testdata/sample-appkey.npvs
go run . testdata/sample-gen2.npvs
go run . -password <password> testdata/sample-passphrase.npvs
```

`-password` is only needed for passphrase-protected files. Without it such files fail with `password required`.

As a library, everything goes through one entry point:

```go
f, err := Parse(data, password) // password may be ""
```

`File` has the detected `Kind` (`KindNPVT` or `KindNPVS`), the envelope `Version`, and either the decrypted `Payloads` (npvt) or a parsed `NPVS` (npvs).

## Formats

Every file starts with the 3 byte magic `NPV`. The 4th byte selects the format:

| Bytes | Format | Notes |
|-------|--------|-------|
| `NPVT` | npvt | Base64 blobs, decrypted with a white-box AES-CTR variant. Several blobs can be concatenated. |
| `NPVS` + `0x01` | npvs V1 | JSON header, one encrypted body. Key is wrapped by an app key or a passphrase (PBKDF2-HMAC-SHA256). |
| `NPVS` + `0x05` | npvs V5 | Binary header with encrypted metadata, followed by encrypted fields (items). |

### Code layout

| File | Purpose |
|------|---------|
| [parse.go](parse.go) | `Parse`: reads the magic and dispatches on format and version |
| [npvs.go](npvs.go) | Types, constants and helpers shared by npvs V1 and V5 |
| [npvs1.go](npvs1.go) | npvs V1 parser |
| [npvs5.go](npvs5.go) | npvs V5 parser |
| [npvt.go](npvt.go) | npvt parser |
| [whitebox.go](whitebox.go) | White-box cipher used by npvt and the V1 app key |
| [reader.go](reader.go) | Bounds-checked big-endian byte reader |
| [errors.go](errors.go) | Error values |

## Tests

```sh
go test ./...
```

The sample files in `testdata/` are used as fixtures.

## Credits / Links

* Project reference (This Project is base off SaKit): [https://github.com/AmirStillAlive/SaKit](https://github.com/AmirStillAlive/SaKit)
