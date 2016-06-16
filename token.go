package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Token struct {
	JWT       *JWT
	algorithm Algorithm
	Raw       *RawToken // The raw token.
	Header    *Header   // The first part of the token.
	Payload   *Payload  // The second part of the token.
}

func NewToken(jwt *JWT, algorithm string) (*Token, error) {
	// Check algorithm.
	alg, support := jwt.algorithms[algorithm]
	if !support {
		return nil, fmt.Errorf("Not support algorithm: %s.", algorithm)
	}

	// Create payload instance.
	now := time.Now()

	payload := &Payload{
		Iss:   jwt.issuer,
		Iat:   now.Unix(),
		Exp:   now.Unix() + jwt.ttl,
		Extra: make(map[string]interface{}, 0),
	}

	return &Token{
		JWT:       jwt,
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
		JWT:       jwt,
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
	if err := t.ValidateExpiration(); err != nil {
		return err
	}

	if err := t.ValidateIssuer(); err != nil {
		return err
	}

	return nil
}

func (t *Token) ValidateIssuer() error {
	// Check issuer if set.
	if len(t.JWT.issuer) > 0 {
		if strings.Compare(t.JWT.issuer, t.Payload.Iss) != 0 {
			return ErrInvalidIssuer
		}
	}

	return nil
}

func (t *Token) ValidateExpiration() error {
	// Check expiration time.
	if t.Payload.Exp <= time.Now().Unix() {
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
