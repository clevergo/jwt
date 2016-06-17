package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"
)

// Encode JWT part by Base64.URLEncoding.
func Encode(part []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(part), "=")
}

// Decode JWT part by Base64.URLEncoding.
func Decode(part string) ([]byte, error) {
	if l := len(part) % 4; l > 0 {
		part += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(part)
}

// Parse PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey
	}

	return pkey, nil
}

// Read bytes from file.
func ReadBytes(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}
