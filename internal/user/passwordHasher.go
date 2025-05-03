package user

import "golang.org/x/crypto/bcrypt"

type BcryptHasher struct{}

func (BcryptHasher) Hash(pw []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
}

func (BcryptHasher) Compare(hash, pw []byte) error {
	return bcrypt.CompareHashAndPassword(hash, pw)
}
