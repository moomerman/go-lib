package autocert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"path"

	"github.com/moomerman/go-lib/kvstore"
	"github.com/xenolf/lego/certcrypto"
	"github.com/xenolf/lego/lego"
	"github.com/xenolf/lego/registration"
)

// User implements the required interface for acme
type User struct {
	Email        string
	Registration *registration.Resource
	privateKey   crypto.PrivateKey
}

// GetEmail returns the user email
func (u *User) GetEmail() string {
	return u.Email
}

// GetRegistration returns the user registration
func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the user privat key
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.privateKey
}

// user finds or creates a new user private key
func (m *Manager) user(ctx context.Context, req *Request) (registration.User, error) {
	email := m.Email // TODO: allow per-request Email addresses
	m.usersMu.Lock()
	defer m.usersMu.Unlock()
	if m.users == nil {
		m.users = map[string]registration.User{}
	}
	if m.users[email] != nil {
		return m.users[email], nil
	}
	user, err := m.userFromStore(ctx, email)
	if err != nil && err != kvstore.ErrCacheMiss {
		return nil, err
	}
	if err == nil {
		m.users[email] = user
		return user, nil
	}
	user, err = m.createUser(ctx, email)
	if err != nil {
		return nil, err
	}
	m.users[email] = user
	return user, nil
}

func (m *Manager) userFromStore(ctx context.Context, email string) (registration.User, error) {
	data, err := m.Store.Get(m.userCacheKey(email))
	if err != nil {
		return nil, err
	}
	privateKey, err := unmarshalPrivateKey(data)
	if err != nil {
		return nil, err
	}
	data, err = m.Store.Get(m.userAccountCacheKey(email))
	if err != nil {
		return nil, err
	}
	user := &User{}
	err = json.Unmarshal(data, user)
	if err != nil {
		return nil, err
	}
	user.privateKey = privateKey
	return user, nil
}

func (m *Manager) createUser(ctx context.Context, email string) (registration.User, error) {
	log.Println("[autocert] creating user", email)
	if err := m.getLock(email); err != nil {
		return nil, err
	}
	defer m.releaseLock(email)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	user := &User{Email: email, privateKey: privateKey}

	config := lego.NewConfig(user)
	config.CADirURL = m.Endpoint
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}) // FIXME: hardcoded acceptance
	if err != nil {
		return nil, err
	}
	user.Registration = reg
	// if m.Prompt(reg.TosURL) {
	// 	if err := client.AgreeToTOS(); err != nil {
	// 		return nil, err
	// 	}
	// } else {
	// 	return nil, errors.New("terms of service were rejected")
	// }
	data, err := marshalPrivateKey(user.GetPrivateKey())
	if err != nil {
		return nil, err
	}
	err = m.Store.Put(m.userCacheKey(email), data)
	if err != nil {
		return nil, err
	}
	account, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := m.Store.Put(m.userAccountCacheKey(email), []byte(account)); err != nil {
		return nil, err
	}
	return user, nil
}

func (m *Manager) userCacheKey(email string) string {
	return path.Join(m.cacheKeyPrefix(), email, email+".key")
}

func (m *Manager) userAccountCacheKey(email string) string {
	return path.Join(m.cacheKeyPrefix(), email, email+".json")
}
