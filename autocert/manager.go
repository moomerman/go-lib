package autocert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
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
	req.hostHash = hash(req.Hosts)
	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()

	// check for an existing certificate request
	var existing *Request
	for _, r := range m.requests {
		if r.hostHash == req.hostHash {
			existing = r
		}
	}

	if existing == nil {
		m.requests = append(m.requests, req)
	} else {
		log.Println("[autocert]", "skip existing certificate request", req)
	}
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
		auth, err := m.Store.Get(m.certChallengeCacheKey(r.Host))
		if err != nil {
			log.Println("[autocert]", "HTTPHandler", r.Host, r.URL.Path, token, err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if !strings.HasPrefix(string(auth), token) {
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

// Status returns a map with the current status of the certificates in the store
func (m *Manager) Status() map[string]interface{} {
	// iterate over the requests, show the status, expiry, any errors
	s := make(map[string]interface{})

	for _, r := range m.requests {
		status := "pending"
		var expires time.Duration
		remaining := 0
		if r.certificate != nil {
			status = "active"
			expiry, err := expiry(r.certificate)
			if err == nil {
				expires = expiry.Sub(time.Now())
				remaining = int(expiry.Sub(time.Now()) / (time.Hour * 24))
			}
		}

		s[strings.Join(r.Hosts, ",")] = struct {
			Status    string
			Hash      string
			Expires   time.Duration
			Remaining int
		}{status, r.hostHash, expires, remaining}
	}

	return s
}

// cert returns an existing certificate or requests a new one
func (m *Manager) cert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	req.certificateMu.Lock()
	defer req.certificateMu.Unlock()
	if req.certificate != nil {
		if m.expiring(req.certificate) {
			cert, err := m.renewCert(ctx, req)
			if err != nil {
				m.Notifier.Error(req.Hosts, err.Error())
				return nil, err
			}
			m.Notifier.Renewed(req.Hosts)
			req.certificate = cert
		}
		return req.certificate, nil
	}
	cert, err := m.certFromStore(ctx, req)
	if err != nil && err != kvstore.ErrCacheMiss {
		return nil, err
	}
	if err == nil {
		if m.expiring(cert) {
			cert, err = m.renewCert(ctx, req)
			if err != nil {
				m.Notifier.Error(req.Hosts, err.Error())
				return nil, err
			}
			m.Notifier.Renewed(req.Hosts)
		}
		req.certificate = cert
		return cert, nil
	}
	cert, err = m.createCert(ctx, req)
	if err != nil {
		m.Notifier.Error(req.Hosts, err.Error())
		return nil, err
	}
	m.Notifier.Created(req.Hosts)
	req.certificate = cert
	return cert, nil
}

func (m *Manager) certFromStore(ctx context.Context, req *Request) (*tls.Certificate, error) {
	resource, err := m.certificateResourceFromStore(ctx, req)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (m *Manager) certificateResourceFromStore(ctx context.Context, req *Request) (*acme.CertificateResource, error) {
	certData, err := m.Store.Get(m.certCacheKey(req))
	if err != nil {
		return nil, err
	}
	pkData, err := m.Store.Get(m.certPKCacheKey(req))
	if err != nil {
		return nil, err
	}
	metaData, err := m.Store.Get(m.certMetaCacheKey(req))
	if err != nil {
		return nil, err
	}
	resource := &acme.CertificateResource{}
	if err := json.Unmarshal(metaData, resource); err != nil {
		return nil, err
	}
	resource.Certificate = certData
	resource.PrivateKey = pkData
	return resource, nil
}

func (m *Manager) putCertificateResourceInStore(ctd context.Context, req *Request, resource *acme.CertificateResource) error {
	meta, err := json.MarshalIndent(resource, "", "  ")
	if err != nil {
		return err
	}
	if err := m.Store.Put(m.certCacheKey(req), resource.Certificate); err != nil {
		return err
	}
	if err := m.Store.Put(m.certPKCacheKey(req), resource.PrivateKey); err != nil {
		return err
	}
	return m.Store.Put(m.certMetaCacheKey(req), meta)
}

// createCert creates a certificate and stores it or returns an error
func (m *Manager) createCert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	log.Println("[autocert] creating certificate", req.Hosts)
	if err := m.getLock(req.Hosts[0]); err != nil {
		return nil, err
	}
	defer m.releaseLock(req.Hosts[0])
	user, err := m.user(ctx, req)
	if err != nil {
		return nil, err
	}
	client, err := m.client(ctx, req, user)
	if err != nil {
		return nil, err
	}
	resource, err := client.ObtainCertificate(req.Hosts, true, nil, false)
	if err != nil {
		log.Println("[autocert] error obtaining certificate", err)
		return nil, err
	}
	if err := m.putCertificateResourceInStore(ctx, req, resource); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// renewCert renews a certificate and stores it or returns an error
func (m *Manager) renewCert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	log.Println("[autocert] renewing certificate", req.Hosts)
	if err := m.getLock(req.Hosts[0]); err != nil {
		return nil, err
	}
	defer m.releaseLock(req.Hosts[0])
	user, err := m.user(ctx, req)
	if err != nil {
		return nil, err
	}
	client, err := m.client(ctx, req, user)
	if err != nil {
		return nil, err
	}
	resource, err := m.certificateResourceFromStore(ctx, req)
	if err != nil {
		return nil, err
	}
	newResource, err := client.RenewCertificate(*resource, true, false)
	if err != nil {
		log.Println("[autocert] error renewing certificate", err)
		return nil, err
	}
	if err := m.putCertificateResourceInStore(ctx, req, newResource); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(newResource.Certificate, newResource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (m *Manager) client(ctx context.Context, req *Request, user acme.User) (*acme.Client, error) {
	req.clientMu.Lock()
	defer req.clientMu.Unlock()
	if req.client != nil {
		return req.client, nil
	}
	client, err := acme.NewClient(m.Endpoint, user, acme.RSA2048) // test EC256
	if err != nil {
		return nil, err
	}
	provider, err := m.provider(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.DNSProviderName != "" {
		client.SetChallengeProvider(acme.DNS01, provider)
		client.ExcludeChallenges([]acme.Challenge{acme.HTTP01})
	} else {
		client.SetChallengeProvider(acme.HTTP01, provider)
		client.ExcludeChallenges([]acme.Challenge{acme.DNS01})
	}
	req.client = client
	return client, nil
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

func (m *Manager) createUser(ctx context.Context, email string) (acme.User, error) {
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

	client, err := acme.NewClient(m.Endpoint, user, acme.RSA2048) // test EC256
	if err != nil {
		return nil, err
	}
	reg, err := client.Register(true) // FIXME: hardcoded acceptance
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

func (m *Manager) expiring(cert *tls.Certificate) bool {
	x, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	if x.NotAfter.Sub(time.Now()) <= m.renewBefore() {
		return true
	}

	return false
}

// findRequest searches requests to find a matching host and returns an error
// if it can't find one
func (m *Manager) findRequest(host string) (*Request, error) {
	wildcard := "*." + strings.Join(strings.Split(host, ".")[1:], ".")

	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()
	for _, r := range m.requests {
		for _, h := range r.Hosts {
			if h == host || h == wildcard {
				return r, nil
			}
		}
	}
	return nil, errors.New("[autocert] could not find request for host: " + host + " or wildcard: " + wildcard)
}

func (m *Manager) renewBefore() time.Duration {
	if m.RenewBefore > time.Hour {
		return m.RenewBefore
	}
	return 720 * time.Hour // 30 days
}

func (m *Manager) cacheKeyPrefix() string {
	url, _ := url.Parse(m.Endpoint)
	return path.Join("autocert", url.Host)
}

func (m *Manager) certCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.Hosts[0], req.Hosts[0]+".crt")
}

func (m *Manager) certPKCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.Hosts[0], req.Hosts[0]+".key")
}

func (m *Manager) certMetaCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.Hosts[0], req.Hosts[0]+".json")
}

func (m *Manager) certChallengeCacheKey(host string) string {
	return path.Join(m.cacheKeyPrefix(), "challenges", host+".auth")
}

func (m *Manager) userCacheKey(email string) string {
	return path.Join(m.cacheKeyPrefix(), email, email+".key")
}

func (m *Manager) userAccountCacheKey(email string) string {
	return path.Join(m.cacheKeyPrefix(), email, email+".json")
}

func (m *Manager) getLock(key string) error {
	key = path.Join(m.cacheKeyPrefix(), key+".lock")
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	data, err := m.Store.Get(key)
	if err != nil && err != kvstore.ErrCacheMiss {
		return err
	}
	if err == nil && string(data) != hostname {
		return errors.New("unable to obtain lock, owned by: " + string(data))
	}
	if err := m.Store.Put(key, []byte(hostname)); err != nil {
		return err
	}
	data, err = m.Store.Get(key)
	if err != nil && err != kvstore.ErrCacheMiss {
		return err
	}
	if err == nil && string(data) != hostname {
		return errors.New("unable to obtain lock, owned by: " + string(data))
	}
	return nil
}

func (m *Manager) releaseLock(key string) error {
	key = path.Join(m.cacheKeyPrefix(), key+".lock")
	return m.Store.Delete(key)
}

func (m *Manager) provider(ctx context.Context, req *Request) (acme.ChallengeProvider, error) {
	req.providerMu.Lock()
	defer req.providerMu.Unlock()
	if req.provider != nil {
		return req.provider, nil
	}
	if req.DNSProviderName != "" {
		provider, err := GetDNSProvider(req.DNSProviderName, req.DNSCredentials)
		if err != nil {
			return nil, err
		}
		req.provider = provider
		return provider, nil
	}
	req.provider = &HTTPProvider{Manager: m}
	return req.provider, nil
}

func handleHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	log.Println("[autocert]", "handleHTTPRedirect", r.Method, r.Host, r.URL.Path)
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

func expiry(cert *tls.Certificate) (time.Time, error) {
	x, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Now(), err
	}

	return x.NotAfter, nil
}

// hash sorts and hashes all the hostnames so we get a consistent unique identifier
func hash(hosts []string) string {
	sorted := []string{}
	sorted = append(sorted, hosts...)
	sort.Strings(sorted)
	hasher := md5.New()
	hasher.Write([]byte(strings.Join(sorted, ",")))
	return hex.EncodeToString(hasher.Sum(nil))
}
