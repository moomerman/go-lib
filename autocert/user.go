package autocert

import (
	"crypto"

	"github.com/xenolf/lego/acme"
)

// User implements the required interface for acme
type User struct {
	email        string
	registration *acme.RegistrationResource
	privateKey   crypto.PrivateKey
}

// GetEmail returns the user email
func (u *User) GetEmail() string {
	return u.email
}

// GetRegistration returns the user registration
func (u *User) GetRegistration() *acme.RegistrationResource {
	return u.registration
}

// SetRegistration sets the user registration
func (u *User) SetRegistration(reg *acme.RegistrationResource) {
	u.registration = reg
}

// GetPrivateKey returns the user privat key
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.privateKey
}
