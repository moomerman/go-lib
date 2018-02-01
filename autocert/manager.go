package autocert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/moomerman/go-lib/kvstore"
	"github.com/xenolf/lego/acme"
)

// Manager is a stateful certificate manager built on top of acme.Client.
// It obtains and refreshes certificates automatically using "http-01",
// and "dns-01" challenge types, as well as providing them
// to a TLS server via tls.Config.
//
// You must specify a cache implementation, such as DirCache, ConsulCache or
// EtcdCache to reuse obtained certificates across program restarts.
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
	// Manager passes the Cache certificates data encoded in PEM, with private/public
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
		log.Println("[go-certs]", "challenge", r.Host, r.URL.Path, token)

		auth, err := m.getPendingHTTPChallenge(r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		log.Println("[go-certs]", "challenge", token, auth)

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
	return nil, nil
}

// renewCert renews a certificate and caches it or returns an error
func (m *Manager) renewCert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	return nil, nil
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
	return path.Join("autocert", m.Endpoint)
}

func (m *Manager) certCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.Hosts[0]+".crt")
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
