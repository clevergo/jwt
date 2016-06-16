package jwt

import "errors"

var (
	ErrInvalidKey       = errors.New("Key is invalid or of invalid type")
	ErrHashUnavailable  = errors.New("The requested hash function is unavailable")
	ErrInvalidSignature = errors.New("Signature is invalid")
)

var (
	ErrKeyMustBePEMEncoded = errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPrivateKey    = errors.New("Key is not a valid RSA private key")
	ErrNotRSAPublicKey     = errors.New("Key is not a valid RSA public key")
)

var (
	ErrInvalidIssuer = errors.New("Issuer is invalid.")
	ErrTokenExpired  = errors.New("Token is expired.")
)
