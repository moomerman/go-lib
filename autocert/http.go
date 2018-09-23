package autocert

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
)

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
