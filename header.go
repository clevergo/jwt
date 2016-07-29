// Copyright 2016 HeadwindFly. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
