package jwt

import "strings"

// JWT(JSON WEB TOKEN) Manager.
type JWT struct {
	issuer     string               // Token's issuer.
	ttl        int64                // Time To Live of token(unit: second).
	algorithms map[string]Algorithm // Algorithms for encrypting data.
}

// Create a JWT instance.
func NewJWT(issuer string, ttl int64) *JWT {
	return &JWT{
		issuer:     issuer,
		ttl:        ttl,
		algorithms: make(map[string]Algorithm, 0),
	}
}

// Add Algorithm.
func (jwt *JWT) AddAlgorithm(name string, algorithm Algorithm) {
	jwt.algorithms[strings.ToUpper(name)] = algorithm
}

func (jwt *JWT) Issuer() string {
	return jwt.issuer
}