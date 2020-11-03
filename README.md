# Doubleclick

[![PkgGoDev](https://pkg.go.dev/badge/github.com/matipan/doubleclick)](https://pkg.go.dev/github.com/matipan/doubleclick)

This package implements the decryption of prices according to Google's OpenRTB-DoubleClick cryptography: https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price.

Decoding a price using the examples that Google shows in their website:

```go
icKey, ecKey, err := ParseKeys(base64.URLEncoding, []byte("arO23ykdNqUQ5LEoQ0FVmPkBd7xB5CO89PDZlSjpFxo="), []byte("skU7Ax_NL5pPAFyKdkfZjZz2-VhIN8bjj1rVFOaJ_5o="))
if err != { 
	log.Fatal(err)
}

price, err := DecryptPrice(icKey, ecKey, []byte("YWJjMTIzZGVmNDU2Z2hpN7fhCuPemC32prpWWw"))
if err != nil {
	log.Fatal(err)
}

fmt.Println(price)
// => 1900
```

Encoding a price using a custom initialization vector:

```go
sampleIcKey, sampleEcKey, err = ParseKeys(base64.URLEncoding, []byte("arO23ykdNqUQ5LEoQ0FVmPkBd7xB5CO89PDZlSjpFxo="), []byte("skU7Ax_NL5pPAFyKdkfZjZz2-VhIN8bjj1rVFOaJ_5o="))
if err != nil {
	log.Fatal(err)
}

iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
price := uint64(1900)
encPrice, err := EncryptPrice(sampleIcKey, sampleEcKey, iv, price)
if err != nil {
	log.Fatal(err)
}

fmt.Println(string(encPrice))
// => AAECAwQFBgcICQoLDA0OD-zub_WgSbtPP9GXag
```

# Contributing
Contributions are welcome, however this a simple project that is not bounded to change often. 
