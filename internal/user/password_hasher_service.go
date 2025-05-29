package user

type PasswordHasher interface {
	Hash(password []byte) ([]byte, error)
	Compare(hash, password []byte) error
}
