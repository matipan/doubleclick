// Package doubleclick implements the decryption logic for Google OpenRTB-DoubleClick cryptography.
package doubleclick

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrInvalidPrice is the error returned when the price parsed
	// by DecryptPrice is not correct.
	ErrInvalidPrice = errors.New("price is invalid")
	// ErrInvalidKeys is the error returned when the keys are not
	// valid.
	ErrInvalidKeys = errors.New("invalid keys")
	// ErrInvalidIV is the error returned when the initialization
	// vector is not valid.
	ErrInvalidIV = errors.New("invalid initialization vector")
)

// ParseKeys parses the base64 web-safe encoded keys as explained in Google's documentation:
// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price
// It receives a base64 encoding object since I've noticed some inconsistencies on Google's
// documentation and the keys they provide to Ad buyers.
// If you are following Google's website examples then use `base64.URLEncoding`.
func ParseKeys(enc *base64.Encoding, ic, ec []byte) (icKey []byte, ecKey []byte, err error) {
	icKey = make([]byte, enc.DecodedLen(len([]byte(ic))))
	n, err := enc.Decode(icKey, []byte(ic))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: could not decode price integrity key. Err: %s", ErrInvalidKeys, err)
	}

	icKey = icKey[:n]

	ecKey = make([]byte, enc.DecodedLen(len([]byte(ec))))
	n, err = enc.Decode(ecKey, []byte(ec))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: could not decode price encryption key. Err: %s", ErrInvalidKeys, err)
	}

	ecKey = ecKey[:n]

	return icKey, ecKey, nil
}

// EncryptPrice encrypts the price using the provided initialization vector
// and keys. It encodes the price into a binary array using binary.BigEndian.
// This function implements the encrypting logic as defined here:
// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price#encryption-scheme
func EncryptPrice(icKey, ecKey, iv []byte, price uint64) ([]byte, error) {
	if len(icKey) == 0 || len(ecKey) == 0 {
		return nil, ErrInvalidKeys
	}

	if len(iv) != 16 {
		return nil, ErrInvalidIV
	}

	// generate the pad by getting the first 8 bytes of
	// the hmac hash of the initialization vector
	h := hmac.New(sha1.New, ecKey)
	h.Write(iv)
	pad := h.Sum(nil)[:8]

	// encode the pricer into a binary array and get the
	// encoded price by doing pad xor p
	p := make([]byte, 8)
	binary.BigEndian.PutUint64(p, price)
	encPrice := safeXORBytes(pad, p)

	// generate the signature by concating the price and the
	// initialization vector, do an hmac hash and get the first
	// 4 bytes
	h = hmac.New(sha1.New, icKey)
	h.Write(p)
	h.Write(iv)
	sig := h.Sum(nil)[:4]

	b := make([]byte, 0, len(iv)+len(encPrice)+len(sig))
	buf := bytes.NewBuffer(b)
	buf.Write(iv)
	buf.Write(encPrice)
	buf.Write(sig)
	n := base64.RawURLEncoding.EncodedLen(len(buf.Bytes()))
	msg := make([]byte, n, n)
	base64.RawURLEncoding.Encode(msg, buf.Bytes())

	return msg, nil
}

// DecryptPrice decrypts the price with google's doubleclick cryptography encoding.
// encPrice is an unpadded web-safe base64 encoded string according to RFC 3548.
// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price#decryption_scheme
func DecryptPrice(icKey, ecKey, encPrice []byte) (uint64, error) {
	if len(icKey) == 0 || len(ecKey) == 0 {
		return 0, ErrInvalidKeys
	}

	if len(encPrice) != 38 {
		return 0, fmt.Errorf("%w: invalid encoded price length, expected 38 got %d", ErrInvalidPrice, len(encPrice))
	}

	dprice := make([]byte, base64.RawURLEncoding.DecodedLen(len(encPrice)))
	n, err := base64.RawURLEncoding.Decode(dprice, encPrice)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid base64 string. Err: %s", ErrInvalidPrice, err)
	}
	dprice = dprice[:n]

	if len(dprice) != 28 {
		return 0, fmt.Errorf("%w: invalid decoded price length. Expected 28 got %d", ErrInvalidPrice, len(dprice))
	}

	// encrypted price is composed of parts of fixed lenth. We break it up according to:
	// {initialization_vector (16 bytes)}{encrypted_price (8 bytes)}{integrity (4 bytes)}
	iv, p, sig := dprice[0:16], dprice[16:24], dprice[24:]
	h := hmac.New(sha1.New, ecKey)

	// writes to hmac depend on the writes to sha1, neither of them
	// return an error but they respect the API. We can skip it
	h.Write(iv)
	pricePad := h.Sum(nil)

	price := safeXORBytes(p, pricePad)
	if price == nil {
		return 0, fmt.Errorf("%w: price xor price_pad failed", ErrInvalidPrice)
	}

	// concatenate the decoded price with the initialization vector and get the first
	// four bytes of the hmac hash
	h = hmac.New(sha1.New, icKey)
	h.Write(price)
	h.Write(iv)
	confSig := h.Sum(nil)[:4]
	if bytes.Compare(confSig, sig) != 0 {
		return 0, fmt.Errorf("%w: integrity of price is not valid", ErrInvalidPrice)
	}

	return binary.BigEndian.Uint64(price), nil
}

func safeXORBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}

	if n == 0 {
		return nil
	}

	dst := make([]byte, n)

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return dst
}
