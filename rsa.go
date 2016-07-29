// Copyright 2016 HeadwindFly. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type RSAAlgorithm struct {
	hash       crypto.Hash
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func NewRSAAlgorithm(hash crypto.Hash, publicKey, privateKey interface{}) (*RSAAlgorithm, error) {
	algorithm := &RSAAlgorithm{
		hash: hash,
	}

	if !algorithm.hash.Available() {
		return nil, ErrHashUnavailable
	}

	var err error

	// Register public key.
	switch k := publicKey.(type) {
	case []byte:
		if algorithm.publicKey, err = ParseRSAPublicKeyFromPEM(k); err != nil {
			return nil, err
		}
	case *rsa.PublicKey:
		algorithm.publicKey = k
	default:
		return nil, ErrInvalidKey
	}

	// Register private key.
	switch k := privateKey.(type) {
	case []byte:
		if algorithm.privateKey, err = ParseRSAPrivateKeyFromPEM(k); err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		algorithm.privateKey = k
	default:
		return nil, ErrInvalidKey
	}

	return algorithm, nil
}

// Implements the Verify method from Algorithm.
func (ra *RSAAlgorithm) Verify(data, signature string) error {
	var err error

	// Decode the signature.
	var sig []byte
	if sig, err = Decode(signature); err != nil {
		return err
	}

	hasher := ra.hash.New()
	hasher.Write([]byte(data))

	// Verify the signature.
	return rsa.VerifyPKCS1v15(ra.publicKey, ra.hash, hasher.Sum(nil), sig)
}

// Implements the Encrypt method from Algorithm.
func (ra *RSAAlgorithm) Encrypt(data string) (string, error) {
	hasher := ra.hash.New()
	hasher.Write([]byte(data))

	// Sign the string and return the encoded bytes.
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, ra.privateKey, ra.hash, hasher.Sum(nil)); err == nil {
		return Encode(sigBytes), nil
	} else {
		return "", err
	}
}
