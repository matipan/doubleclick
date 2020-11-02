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

// ParseKeys parses the base64 web-safe encoded keys as explained in Google's documentation:
// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price
func ParseKeys(ic, ec []byte) (icKey []byte, ecKey []byte, err error) {
	icKey = make([]byte, base64.URLEncoding.DecodedLen(len([]byte(ic))))
	n, err := base64.URLEncoding.Decode(icKey, []byte(ic))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: could not decode price integrity key", err)
	}

	icKey = icKey[:n]

	ecKey = make([]byte, base64.URLEncoding.DecodedLen(len([]byte(ec))))
	n, err = base64.URLEncoding.Decode(ecKey, []byte(ec))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: could not decode price encryption key", err)
	}

	ecKey = ecKey[:n]

	return icKey, ecKey, nil
}

// ErrInvalidPrice is the error returned when the price parsed
// by DecryptPrice is not correct.
var ErrInvalidPrice = errors.New("adx price is invalid")

// DecryptPrice decrypts the price with google's doubleclick cryptography encoding.
// encPrice is an unpadded web-safe base64 encoded string according to RFC 3548.
// https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price
func DecryptPrice(icKey, ecKey, encPrice []byte) (uint64, error) {
	if len(icKey) == 0 || len(ecKey) == 0 {
		return 0, errors.New("encryption and integrity keys are required")
	}

	if len(encPrice) != 38 {
		return 0, fmt.Errorf("%w: invalid length, expected 28 got %d", ErrInvalidPrice, len(encPrice))
	}

	dprice := make([]byte, base64.RawURLEncoding.DecodedLen(len(encPrice)))
	n, err := base64.RawURLEncoding.Decode(dprice, encPrice)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid base64 string", err)
	}
	dprice = dprice[:n]

	if len(dprice) != 28 {
		return 0, fmt.Errorf("%w: invalid decoded price length. Expected 28 got %d", ErrInvalidPrice, len(dprice))
	}

	// encrypted price is composed of parts of fixed lenth. We break it up according to:
	// {initialization_vector (16 bytes)}{encrypted_price (8 bytes)}{integrity (4 bytes)}
	iv, p, sig := dprice[0:16], dprice[16:24], dprice[24:]
	h := hmac.New(sha1.New, ecKey)
	n, err = h.Write(iv)
	if err != nil || n != len(iv) {
		return 0, fmt.Errorf("%w: could not write hmac hash for iv. err=%s, n=%d, len(iv)=%d", ErrInvalidPrice, err, n, len(iv))
	}
	pricePad := h.Sum(nil)

	price := safeXORBytes(p, pricePad)
	if price == nil {
		return 0, fmt.Errorf("%w: price xor price_pad failed", ErrInvalidPrice)
	}

	h = hmac.New(sha1.New, icKey)
	n, err = h.Write(price)
	if err != nil || n != len(price) {
		return 0, fmt.Errorf("%w: could not write hmac hash for price. err=%s, n=%d, len(price)=%d", ErrInvalidPrice, err, n, len(price))
	}

	n, err = h.Write(iv)
	if err != nil || n != len(iv) {
		return 0, fmt.Errorf("%w: could not write hmac hash for iv. err=%s, n=%d, len(iv)=%d", ErrInvalidPrice, err, n, len(iv))
	}

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
