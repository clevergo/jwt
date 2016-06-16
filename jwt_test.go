package jwt

import (
	"crypto"
	"testing"
	"time"
)

var (
	publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMk7RZ9BjeiwiGcJl9nUqdnYYG
qSx0mnCP8XdB4DpCgLI+cKw00j7m6a1wkB61g9SmPYmLqoSzBHX7RkMpmyJ7Ib6D
T43/iPWxLesPTlAQYgOmKaT+a297cnOXs7GVz8lZSMc/JdzIgrKXivmDcTrxJZ5o
bAyxk9GQ/zVEVxaxxwIDAQAB
-----END PUBLIC KEY-----`)

	privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDMk7RZ9BjeiwiGcJl9nUqdnYYGqSx0mnCP8XdB4DpCgLI+cKw0
0j7m6a1wkB61g9SmPYmLqoSzBHX7RkMpmyJ7Ib6DT43/iPWxLesPTlAQYgOmKaT+
a297cnOXs7GVz8lZSMc/JdzIgrKXivmDcTrxJZ5obAyxk9GQ/zVEVxaxxwIDAQAB
AoGARO7kT4c7tgk9NyfL4JLWqKOCnM32Z9f+Y9Jmb/EhUHVTGk0XCblqbp6AzbQS
VPF1/wovRbuQeU3gf2neia93f1Esx4336xG2S38e4IvJVkuPDebU43gvlQrVkLqW
wAud4ay2QGbGlA6Sr5ZPVlqoNVZElE4SmZw42T/LvXzvCRECQQD7F6Dwk9irN3VA
lvEDqErkMySTHVDnqiqJKEA2UpHajhM2li6EWJY7z70srSzBVeIe0cYbkHBKqUVO
MtQQwxzpAkEA0JNUpHgvuiw1/5gf4jr2TDGonyhHUDHPDrVQpfaGFLfMYFmaYsQG
//cmW6rkWVxhthSy4mEzldlSO9rD61drLwJBAM3SU5mBB7Vps1JrqEqgNCuVBKEX
Ac+0fEOL2/7rdiWaGoO/XYgc+aEzq1Uo6yvb04wB1ouXvYRl9qqgHZdT6KkCQEnz
MpttkV5stmh8wzEuvoydPq/PVBl2z3bjikiNc1R9JhUzL6282s5+DjeKC5QzUOGB
zTq+Q8/pUWKvWa9jOzkCQD7yioMi2F6gAuPkg77d8/elGOOyBM4R4aj8/svto0wx
moz8u3wUm4HhD99vpIWzLXB2FCb9Bi2T7KQTCskyHac=
-----END RSA PRIVATE KEY-----`)

	hmacKey = []byte("I am HMAC key.")

	jwt *JWT

	issuer = "CleverGo"

	ttl = int64(5)
)

func init() {
	// Craeta a JWT manager.
	jwt = NewJWT(issuer, ttl)

	// Add RSAAlgorithm.
	rs256, err := NewRSAAlgorithm(crypto.SHA256, publicKey, privateKey)
	if err != nil {
		panic(err)
	}
	jwt.AddAlgorithm("RS256", rs256)

	// Add HMACAlgorithm.
	hs256, err := NewHMACAlgorithm(crypto.SHA256, hmacKey)
	if err != nil {
		panic(err)
	}
	jwt.AddAlgorithm("HS256", hs256)
}

func TestRSA(t *testing.T) {
	// Create a new token using RS256.
	token1, err := NewToken(jwt, "RS256")
	if err != nil {
		t.Error(err)
	}
	// Parse token.
	err = token1.Parse()
	if err != nil {
		t.Error(err)
	}

	// Get token by raw token.
	token2, err := NewTokenByRaw(
		jwt,
		token1.Raw.token,
	)
	if err != nil {
		t.Error(err)
	}

	// Validate token2.
	err = token2.Validate()
	if err != nil {
		t.Error(err)
	}

	// Check expiration time.
	// Make sure that the token is expired.
	time.Sleep(time.Duration(ttl+1) * time.Second)

	err = token2.ValidateExpiration()
	if err == nil {
		t.Error("It is impossible that token is valid.")
	}
}

func TestHMAC(t *testing.T) {
	// Create a new token using HS256.
	token, err := NewToken(jwt, "HS256")
	if err != nil {
		t.Error(err)
	}
	// Parse token.
	err = token.Parse()
	if err != nil {
		t.Error(err)
	}

	// Get token by raw token.
	token2, err := NewTokenByRaw(
		jwt,
		token.Raw.token,
	)
	if err != nil {
		t.Error(err)
	}

	// Validate token2.
	err = token2.Validate()
	if err != nil {
		t.Error(err)
	}

	// Check expiration time.
	// Make sure that the token is expired.
	time.Sleep(time.Duration(ttl+1) * time.Second)

	err = token2.ValidateExpiration()
	if err == nil {
		t.Error("It is impossible that token is valid.")
	}
}