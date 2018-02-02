package autocert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/moomerman/go-lib/kvstore"
	"github.com/xenolf/lego/acme"
)

// Manager is a stateful certificate manager.
// It obtains and refreshes certificates automatically using "http-01",
// and "dns-01" challenge types, as well as providing them
// to a TLS server via tls.Config.
//
// You must specify a store implementation, such as DirStore, ConsulStore or
// EtcdStore to reuse obtained certificates across program restarts.
// Otherwise your server is very likely to exceed the certificate
// issuer's request rate limits.
//
// You can provide an optional Notifier implementation that will send
// notifications about certificate issuance, renewal and any errors.
type Manager struct {
	Endpoint string

	// Store optionally stores and retrieves previously-obtained certificates.
	// If nil, certs will only be cached for the lifetime of the Manager.
	//
	// Manager passes the Store certificates data encoded in PEM, with private/public
	// parts combined in a single Cache.Put call, private key first.
	Store kvstore.Store

	// Notifier sends notifications about certificate issuance, renewal or errors
	// If nil, no notifications will be sent.
	Notifier Notifier

	// Prompt specifies a callback function to conditionally accept a CA's Terms of Service (TOS).
	// The registration may require the caller to agree to the CA's TOS.
	// If so, Manager calls Prompt with a TOS URL provided by the CA. Prompt should report
	// whether the caller agrees to the terms.
	//
	// To always accept the terms, the callers can use AcceptTOS.
	Prompt func(tosURL string) bool

	// RenewBefore optionally specifies how early certificates should
	// be renewed before they expire.
	//
	// If zero, they're renewed 30 days before expiration.
	RenewBefore time.Duration

	// Email optionally specifies a contact email address.
	// This is used by CAs, such as Let's Encrypt, to notify about problems
	// with issued certificates.
	//
	// If the Client's account key is already registered, Email is not used.
	Email string

	requestsMu sync.Mutex
	requests   []*Request

	usersMu sync.Mutex
	users   map[string]acme.User
}

// AcceptTOS is a Manager.Prompt function that always returns true to
// indicate acceptance of the CA's Terms of Service during account
// registration.
func AcceptTOS(tosURL string) bool { return true }

// Add adds a Request for the Manager
func (m *Manager) Add(req *Request) {
	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()
	m.requests = append(m.requests, req)
}

// HTTPHandler returns a handler to verify http-01 challenges
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	if fallback == nil {
		fallback = http.HandlerFunc(handleHTTPRedirect)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			fallback.ServeHTTP(w, r)
			return
		}
		token := path.Base(r.URL.Path)
		auth, err := m.getPendingHTTPChallenge(r.Host)
		if err != nil {
			log.Println("[autocert]", "HTTPHandler", r.Host, r.URL.Path, token, err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if !strings.HasPrefix(auth, token) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		fmt.Fprintf(w, "%s", auth)
	})
}

// GetCertificate implements the tls.Config.GetCertificate hook.
// It provides a TLS certificate for a given hello.ServerName host
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	request, err := m.findRequest(hello.ServerName)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	return m.cert(ctx, request)
}

// cert returns an existing certificate or requests a new one
func (m *Manager) cert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	req.certificateMu.Lock()
	defer req.certificateMu.Unlock()

	if req.certificate != nil {
		if m.expiring(req.certificate) {
			return m.renewCert(ctx, req)
		}
		return req.certificate, nil
	}

	cached, err := m.Store.Get(m.certCacheKey(req))
	if err != nil {
		return m.createCert(ctx, req)
	}
	fmt.Println(cached)
	return nil, nil
}

// createCert creates a certificate and caches it or returns an error
func (m *Manager) createCert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	user, err := m.user(ctx, req)
	if err != nil {
		return nil, err
	}
	log.Println("createCert", user)
	return nil, nil
}

// renewCert renews a certificate and caches it or returns an error
func (m *Manager) renewCert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	return nil, nil
}

// user finds or creates a new user private key
func (m *Manager) user(ctx context.Context, req *Request) (acme.User, error) {
	email := m.Email // TODO: allow per-request Email addresses
	m.usersMu.Lock()
	defer m.usersMu.Unlock()
	if m.users == nil {
		m.users = map[string]acme.User{}
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

func (m *Manager) userFromStore(ctx context.Context, email string) (acme.User, error) {
	data, err := m.Store.Get(m.userCacheKey(email))
	if err != nil {
		return nil, err
	}
	privateKey, err := unmarshalPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return &User{email: email, privateKey: privateKey}, nil
}

func (m *Manager) createUser(ctx context.Context, email string) (acme.User, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	user := &User{email: email, privateKey: privateKey}

	client, err := acme.NewClient(m.Endpoint, user, acme.RSA2048)
	if err != nil {
		return nil, err
	}
	reg, err := client.Register()
	if err != nil {
		return nil, err
	}
	user.registration = reg
	if m.Prompt(reg.TosURL) {
		if err := client.AgreeToTOS(); err != nil {
			return nil, err
		}
	}
	data, err := marshalPrivateKey(user.GetPrivateKey())
	if err != nil {
		return nil, err
	}
	err = m.Store.Put(m.userCacheKey(email), data)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (m *Manager) expiring(cert *tls.Certificate) bool {
	expiry, err := acme.GetPEMCertExpiration(cert.Certificate[0])
	if err != nil {
		return true
	}
	if expiry.Sub(time.Now()) <= m.renewBefore() {
		return true
	}

	return false
}

// findRequest searches requests to find a matching host and returns an error
// if it can't find one
func (m *Manager) findRequest(host string) (*Request, error) {
	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()
	for _, r := range m.requests {
		for _, h := range r.Hosts {
			if h == host {
				return r, nil
			}
		}
	}
	return nil, errors.New("could not find request for: " + host)
}

func (m *Manager) renewBefore() time.Duration {
	if m.RenewBefore > time.Hour {
		return m.RenewBefore
	}
	return 720 * time.Hour // 30 days
}

func (m *Manager) getPendingHTTPChallenge(host string) (string, error) {
	// TODO: retrieve from Cache
	return "", nil
}

func (m *Manager) cacheKeyPrefix() string {
	url, _ := url.Parse(m.Endpoint)
	return path.Join("autocert", url.Host)
}

func (m *Manager) certCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.Hosts[0]+".crt")
}

func (m *Manager) userCacheKey(email string) string {
	return path.Join(m.cacheKeyPrefix(), email+".key")
}

func handleHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Use HTTPS", http.StatusBadRequest)
		return
	}
	target := "https://" + stripPort(r.Host) + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusFound)
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return net.JoinHostPort(host, "443")
}

func marshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var pemType string
	var keyBytes []byte
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		var err error
		pemType = "EC"
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		pemType = "RSA"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	}
	pemKey := pem.Block{Type: pemType + " PRIVATE KEY", Bytes: keyBytes}
	return pem.EncodeToMemory(&pemKey), nil
}

func unmarshalPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyBytes)
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}
	return nil, errors.New("unknown private key type")
}
