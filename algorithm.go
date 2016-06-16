package jwt

type Algorithm interface {
	Encrypt(data string) (string, error)
	Verify(data, signature string) error
}
