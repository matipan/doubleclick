package doubleclick

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/matryer/is"
)

var (
	sampleIcKey, sampleEcKey []byte
)

func TestMain(m *testing.M) {
	var err error
	sampleIcKey, sampleEcKey, err = ParseKeys(base64.URLEncoding, []byte("arO23ykdNqUQ5LEoQ0FVmPkBd7xB5CO89PDZlSjpFxo="), []byte("skU7Ax_NL5pPAFyKdkfZjZz2-VhIN8bjj1rVFOaJ_5o="))
	if err != nil {
		panic(fmt.Sprintf("could not initialise adx sample keys: %s", err))
	}

	os.Exit(m.Run())
}

func TestEncryptDecryptPrice(t *testing.T) {
	is := is.New(t)

	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	price := uint64(1900)
	encPrice, err := EncryptPrice(sampleIcKey, sampleEcKey, iv, price)
	is.NoErr(err)

	decryptedPrice, err := DecryptPrice(sampleIcKey, sampleEcKey, encPrice)
	is.NoErr(err)
	is.Equal(decryptedPrice, price)
}

func TestEncryptPrice(t *testing.T) {
	cases := []struct {
		name          string
		icKey, ecKey  []byte
		iv            []byte
		price         uint64
		expectedPrice []byte
		expectedErr   error
	}{
		{
			name:        "integrity key is invalid",
			ecKey:       []byte{1, 2, 3},
			iv:          []byte{1, 2, 3},
			price:       1,
			expectedErr: ErrInvalidKeys,
		},
		{
			name:        "encryption key is invalid",
			icKey:       []byte{1, 2, 3},
			iv:          []byte{1, 2, 3},
			price:       1,
			expectedErr: ErrInvalidKeys,
		},
		{
			name:        "initialization vector is invalid",
			icKey:       []byte{1, 2, 3},
			ecKey:       []byte{1, 2, 3},
			price:       1,
			expectedErr: ErrInvalidIV,
		},
		{
			name:          "price is generated successfully",
			icKey:         sampleIcKey,
			ecKey:         sampleEcKey,
			iv:            []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			expectedPrice: []byte("AAECAwQFBgcICQoLDA0OD-zub_WgSbtPP9GXag"),
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			is := is.New(t)

			price, err := EncryptPrice(test.icKey, test.ecKey, test.iv, test.price)
			is.Equal(test.expectedPrice, price)
			is.True(errors.Is(err, test.expectedErr))
		})
	}
}

func TestDecryptxPrice(t *testing.T) {
	cases := []struct {
		name          string
		price         []byte
		icKey, ecKey  []byte
		expectedPrice uint64
		expectedErr   error
	}{
		{
			name:          "price is 1900",
			price:         []byte("YWJjMTIzZGVmNDU2Z2hpN7fhCuPemCAWJRxOgA"),
			icKey:         sampleIcKey,
			ecKey:         sampleEcKey,
			expectedPrice: 1900,
			expectedErr:   nil,
		},
		{
			name:        "signature in price is not valid",
			price:       []byte("YWJjMTIzZGVmNDU2Z2hpN7fhCuPemCAWJRxOlA"),
			icKey:       sampleIcKey,
			ecKey:       sampleEcKey,
			expectedErr: ErrInvalidPrice,
		},
		{
			name:          "price has invalid length",
			price:         []byte{1, 2, 3},
			icKey:         sampleIcKey,
			ecKey:         sampleEcKey,
			expectedPrice: 0,
			expectedErr:   ErrInvalidPrice,
		},
		{
			name:          "price is invalid base64",
			price:         []byte("Y!YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"),
			icKey:         sampleIcKey,
			ecKey:         sampleEcKey,
			expectedPrice: 0,
			expectedErr:   ErrInvalidPrice,
		},
		{
			name:        "integrity key is empty",
			price:       []byte("test"),
			icKey:       nil,
			ecKey:       sampleEcKey,
			expectedErr: ErrInvalidKeys,
		},
		{
			name:        "encryption key is empty",
			price:       []byte("test"),
			icKey:       nil,
			ecKey:       sampleEcKey,
			expectedErr: ErrInvalidKeys,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			is := is.New(t)

			price, err := DecryptPrice(test.icKey, test.ecKey, test.price)
			is.Equal(test.expectedPrice, price)
			is.True(errors.Is(err, test.expectedErr))
		})
	}
}
