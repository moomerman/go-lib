package autocert_test

import (
	"crypto/tls"
	"net/http"

	"github.com/moomerman/autocert"
	"github.com/moomerman/go-lib/kvstore/dir"
)

func ExampleManager() {
	m := &autocert.Manager{
		Endpoint: "https://acme-staging.api.letsencrypt.org/directory",
		Store:    dir.Store("secret-dir"),
		Notifier: autocert.SlackNotifier("https://....."),
		Prompt:   autocert.AcceptTOS,
		Email:    "user@example.com",
	}

	// HTTP verification
	m.Add(&autocert.Request{
		Hosts: []string{"example.com", "www.example.com"},
	})

	// DNS verification
	m.Add(&autocert.Request{
		Hosts:           []string{"example.com"},
		DNSProviderName: autocert.DNSimpleProvider,
		DNSCredentials:  []string{"API_KEY"},
	})

	go http.ListenAndServe(":http", m.HTTPHandler(nil))
	s := &http.Server{
		Addr:      ":https",
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	s.ListenAndServeTLS("", "")
}
