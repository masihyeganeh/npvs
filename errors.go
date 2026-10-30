package main

import "errors"

var ErrNotNPV = errors.New("not a NPV file")
var ErrUnsupportedEnvelopeVersion = errors.New("envelope version not supported")
var ErrUnsupportedHeaderVersion = errors.New("header version not supported")
var ErrUnsupportedBodyVersion = errors.New("body version not supported")
var ErrUnsupportedMethod = errors.New("unsupported method")
var ErrMalformedPayload = errors.New("malformed payload")
var ErrUnsupportedKdf = errors.New("key derivation function not supported")
var ErrUnsupportedKeyID = errors.New("key ID not supported")
var ErrPasswordRequired = errors.New("password required")
var ErrRecipientWithPrivateKeyNotImplemented = errors.New("recipient with private key not implemented")
var ErrTooManyRecipients = errors.New("too many recipients")
