package autocert

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log"
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
	// create a unique key for this set of Hosts and tag on a visible identifier
	req.hostHash = hash(req.Hosts) + "-" + req.Hosts[0]
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

	// TODO: at this point we should ensure we have a background monitor in
	// place to renew certificates and ocsp responses, once every 24 hours?
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
			Error     error
		}{status, r.hostHash, expires, remaining, r.error}
	}

	return s
}

// Monitor starts a goroutine to renew certificates / OCSP daily
func (m *Manager) Monitor() {
	go func() {
		time.Sleep(5 * time.Second)
		log.Println("[autocert]", "starting background monitor, runs every 24h")
		for {
			m.check()
			time.Sleep(24 * time.Hour)
		}
	}()
}

func (m *Manager) check() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, req := range m.requests {
		m.cert(ctx, req)
	}
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
		provider, err := getDNSProvider(req.DNSProviderName, req.DNSCredentials)
		if err != nil {
			return nil, err
		}
		req.provider = provider
		return provider, nil
	}
	req.provider = &httpProvider{Manager: m}
	return req.provider, nil
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
