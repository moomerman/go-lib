package autocert

import (
	"crypto"

	"github.com/xenolf/lego/acmev2"
)

// User implements the required interface for acme
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	privateKey   crypto.PrivateKey
}

// GetEmail returns the user email
func (u *User) GetEmail() string {
	return u.Email
}

// GetRegistration returns the user registration
func (u *User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

// GetPrivateKey returns the user privat key
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.privateKey
}
