# Doubleclick

[![PkgGoDev](https://pkg.go.dev/badge/github.com/matipan/doubleclick)](https://pkg.go.dev/github.com/matipan/doubleclick)

This package implements the decryption of prices according to Google's OpenRTB-DoubleClick cryptography: https://developers.google.com/authorized-buyers/rtb/response-guide/decrypt-price.

Decoding a price using examples by Google shown above:

```go
icKey, ecKey, err := ParseKeys([]byte("arO23ykdNqUQ5LEoQ0FVmPkBd7xB5CO89PDZlSjpFxo="), []byte("skU7Ax_NL5pPAFyKdkfZjZz2-VhIN8bjj1rVFOaJ_5o="))
if err != { 
	log.Fatal(err)
}

price, err := DecryptPrice(icKey, ecKey, []byte("YWJjMTIzZGVmNDU2Z2hpN7fhCuPemC32prpWWw"))
if err != nil {
	log.Fatal(err)
}

fmt.Println(price)
```

# CONTRIBUTING
Contributions are welcome, however this a simple project that is not bounded to change often. I might add the encryption logic soon.
