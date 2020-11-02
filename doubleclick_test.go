package doubleclick

import (
	"errors"
	"testing"

	"github.com/matryer/is"
)

func TestDecryptxPrice(t *testing.T) {
	var err error
	icKey, ecKey, err := ParseKeys([]byte("arO23ykdNqUQ5LEoQ0FVmPkBd7xB5CO89PDZlSjpFxo="), []byte("skU7Ax_NL5pPAFyKdkfZjZz2-VhIN8bjj1rVFOaJ_5o="))
	if err != nil {
		t.Fatalf("could not initialise adx sample keys: %s", err)
	}

	cases := []struct {
		name          string
		price         []byte
		expectedPrice uint64
		expectedErr   error
	}{
		{
			name:          "price has invalid lenght",
			price:         []byte{1, 2, 3},
			expectedPrice: 0,
			expectedErr:   ErrInvalidPrice,
		},
		{
			name:          "price is 1900",
			price:         []byte("YWJjMTIzZGVmNDU2Z2hpN7fhCuPemCAWJRxOgA"),
			expectedPrice: 1900,
			expectedErr:   nil,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			is := is.New(t)

			price, err := DecryptPrice(icKey, ecKey, test.price)
			is.Equal(test.expectedPrice, price)
			is.True(errors.Is(err, test.expectedErr))
		})
	}
}
