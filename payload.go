// Copyright 2016 HeadwindFly. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt

type Payload struct {
	Exp   int64                  `json:"exp"`   // expiration time
	Iss   string                 `json:"iss"`   // issuer
	Sub   string                 `json:"sub"`   // subject
	Aud   string                 `json:"aud"`   // audience
	Nbf   int64                  `json:"nbf"`   // not before
	Iat   int64                  `json:"iat"`   // issued at
	Jti   string                 `json:"jti"`   // jwt id
	Extra map[string]interface{} `json:"extra"` // extra
}

func NewPayload() *Payload {
	return &Payload{
		Extra: make(map[string]interface{}, 0),
	}
}
