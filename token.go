// Copyright 2016 HeadwindFly. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Token struct {
	jwt       *JWT
	algorithm Algorithm
	Raw       *RawToken // The raw token.
	Header    *Header   // The first part of the token.
	Payload   *Payload  // The second part of the token.
}

func NewToken(jwt *JWT, algorithm, subject, audience string) (*Token, error) {
	// Check algorithm.
	alg, support := jwt.algorithms[algorithm]
	if !support {
		return nil, fmt.Errorf("Not support algorithm: %s.", algorithm)
	}

	// Create payload instance.
	payload := jwt.NewPayload(subject, audience)

	return &Token{
		jwt:       jwt,
		algorithm: alg,
		Raw:       &RawToken{},
		Header:    NewHeader(algorithm),
		Payload:   payload,
	}, nil
}

func NewTokenByRaw(jwt *JWT, token string) (*Token, error) {
	// Get raw token.
	raw, err := NewRawToken(token)
	if err != nil {
		return nil, err
	}

	// Parse first part of token(Header).
	header := Header{}

	headerPart, err := Decode(raw.header)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(headerPart, &header)
	if err != nil {
		return nil, err
	}

	// Check algorithm
	algorithm, support := jwt.algorithms[header.Alg]
	if !support {
		return nil, fmt.Errorf("Not support algorithm: %s.", header.Alg)
	}

	// Parse second part of token(Payload).
	payloadPart, err := Decode(raw.payload)
	if err != nil {
		return nil, err
	}
	payload := NewPayload()
	json.Unmarshal(payloadPart, payload)
	if err != nil {
		return nil, err
	}

	// Check signature.
	err = algorithm.Verify(raw.header+"."+raw.payload, raw.signature)
	if err != nil {
		return nil, err
	}

	return &Token{
		jwt:       jwt,
		Raw:       raw,
		algorithm: algorithm,
		Header:    &header,
		Payload:   payload,
	}, nil
}

// Parse token's header, payload and signature to raw.
func (t *Token) Parse() error {
	// Header
	header, err := json.Marshal(t.Header)
	if err != nil {
		return err
	}
	t.Raw.header = Encode(header)

	// Payload
	payload, err := json.Marshal(t.Payload)
	if err != nil {
		return err
	}
	t.Raw.payload = Encode(payload)

	twoParts := t.Raw.header + "." + t.Raw.payload
	// Signature
	t.Raw.signature, err = t.algorithm.Encrypt(twoParts)
	if err != nil {
		return err
	}

	t.Raw.token = twoParts + "." + t.Raw.signature

	return nil
}

func (t *Token) Validate() error {
	now := time.Now()
	if err := t.ValidateExpiration(now); err != nil {
		return err
	}

	if err := t.ValidateNotBefore(now); err != nil {
		return err
	}

	if err := t.ValidateIssuer(); err != nil {
		return err
	}

	return nil
}

func (t *Token) ValidateIssuer() error {
	// Check issuer if set.
	if len(t.jwt.issuer) > 0 {
		if strings.Compare(t.jwt.issuer, t.Payload.Iss) != 0 {
			return ErrInvalidIssuer
		}
	}

	return nil
}

// Check expiration time.
func (t *Token) ValidateExpiration(now time.Time) error {
	if t.Payload.Exp <= now.Unix() {
		return ErrTokenExpired
	}

	return nil
}

// Check Not Before
func (t *Token) ValidateNotBefore(now time.Time) error {
	if (t.Payload.Nbf > 0) && (t.Payload.Nbf > now.Unix()) {
		return ErrTokenExpired
	}

	return nil
}

type RawToken struct {
	token     string // Raw token(URLEncode(header) + "." + URLEncode(payload) + "." + URLEncode(signature)).
	header    string // Token's header.
	payload   string // Token's Payload.
	signature string // Token's Signature.
}

func NewRawToken(token string) (*RawToken, error) {
	// Break down raw token into three parts.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("The raw token is invalid: %s.", token)
	}

	return &RawToken{
		token:     token,
		header:    parts[0],
		payload:   parts[1],
		signature: parts[2],
	}, nil
}

func (rt *RawToken) Token() string {
	return rt.token
}

func (rt *RawToken) Header() string {
	return rt.header
}

func (rt *RawToken) Payload() string {
	return rt.payload
}

func (rt *RawToken) Signature() string {
	return rt.signature
}
