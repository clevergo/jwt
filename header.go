package jwt

import "strings"

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func NewHeader(algorithm string) *Header {
	return &Header{
		Alg: strings.ToUpper(algorithm),
		Typ: "JWT",
	}
}
