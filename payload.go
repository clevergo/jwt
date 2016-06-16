package jwt

type Payload struct {
	Exp       int64                  `json:"exp"`
	Iss       string                 `json:"iss"`
	Sub       string                 `json:"sub"`
	Aud       string                 `json:"aud"`
	Nbf       int64                  `json:"nbf"`
	Iat       int64                  `json:"iat"`
	Jti       string                 `json:"jti"`
	UserID    int64                  `json:"uid"`
	UserEmail string                 `json:"email"`
	UserName  string                 `json:"name"`
	Extra     map[string]interface{} `json:"extra"`
}

func NewPayload() *Payload {
	return &Payload{
		Extra: make(map[string]interface{}, 0),
	}
}
