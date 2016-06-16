package jwt

import (
	"crypto"
	"crypto/hmac"
)

type HMACAlgorithm struct {
	hash crypto.Hash
	key  []byte
}

func NewHMACAlgorithm(hash crypto.Hash, key []byte) (*HMACAlgorithm, error) {
	algorithm := &HMACAlgorithm{
		hash: hash,
		key:  key,
	}

	if !algorithm.hash.Available() {
		return nil, ErrHashUnavailable
	}

	return algorithm, nil
}

// Implements the Verify method from Algorithm.
func (h *HMACAlgorithm) Verify(data, signature string) error {
	// Decode signature, for comparison.
	sig, err := Decode(signature)
	if err != nil {
		return err
	}

	// Validate signature.
	hasher := hmac.New(h.hash.New, h.key)
	hasher.Write([]byte(data))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrInvalidSignature
	}

	// Validate successfully.
	return nil
}

// Implements the Encrypt method from Algorithm.
func (h *HMACAlgorithm) Encrypt(data string) (string, error) {
	hasher := hmac.New(h.hash.New, h.key)
	hasher.Write([]byte(data))

	return Encode(hasher.Sum(nil)), nil
}
