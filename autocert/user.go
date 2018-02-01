package autocert

import (
	"crypto"

	"github.com/xenolf/lego/acme"
)

// User implements the required interface for acme
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
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
	return u.key
}

// SetKey sets the private key for the user
func (u *User) SetKey(key crypto.PrivateKey) {
	u.key = key
}
