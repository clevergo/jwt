// Copyright 2016 HeadwindFly. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt

import (
	"fmt"
	"github.com/clevergo/uuid"
	"strings"
	"time"
)

// JWT(JSON WEB TOKEN) Manager.
type JWT struct {
	issuer        string               // Token's issuer.
	ttl           int64                // Time To Live of token(unit: second).
	notBefore     int64                // Not before. See also to nbf of jwt.
	autoCreateJTI bool                 // Auto create jwt id(jti).
	algorithms    map[string]Algorithm // Algorithms for encrypting/decrypting data.
}

// Create a JWT instance.
func NewJWT(issuer string, ttl int64) *JWT {
	return &JWT{
		issuer:     issuer,
		ttl:        ttl,
		algorithms: make(map[string]Algorithm, 0),
	}
}

func (j *JWT) SetNotBefore(t time.Time) {
	j.notBefore = t.Unix()
}

func (j *JWT) SetAutoCreateJTI(auto bool) {
	j.autoCreateJTI = auto
}

// Add Algorithm.
func (j *JWT) AddAlgorithm(name string, algorithm Algorithm) {
	j.algorithms[strings.ToUpper(name)] = algorithm
}

func (j *JWT) Issuer() string {
	return j.issuer
}

func (j *JWT) TTL() int64 {
	return j.ttl
}

func (j *JWT) NewToken(algorithm, subject, audience string) (*Token, error) {
	return NewToken(j, algorithm, subject, audience)
}

func (j *JWT) NewTokenByRaw(token string) (*Token, error) {
	return NewTokenByRaw(j, token)
}

func (j *JWT) NewPayload(subject, audience string) *Payload {
	now := time.Now()

	return &Payload{
		Exp:   now.Unix() + j.ttl,
		Iss:   j.issuer,
		Sub:   subject,
		Aud:   audience,
		Nbf:   j.notBefore,
		Iat:   now.Unix(),
		Jti:   j.JTI(),
		Extra: make(map[string]interface{}, 0),
	}
}

func (j *JWT) JTI() string {
	if j.autoCreateJTI {
		return fmt.Sprintf("%s", uuid.NewV4())
	}
	return ""
}
