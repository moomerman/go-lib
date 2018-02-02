package main

import (
	"crypto/tls"
	"net/http"

	"github.com/moomerman/go-lib/autocert"
	"github.com/moomerman/go-lib/kvstore/dir"
)

func main() {

	m := &autocert.Manager{
		Endpoint: "https://acme-staging.api.letsencrypt.org/directory",
		Store:    dir.Store("secret-dir"), // or consul.Store, etcd.Store
		Notifier: autocert.SlackNotifier("https://hooks.slack.com/services/..."),
		Prompt:   autocert.AcceptTOS,
		Email:    "user@example.com",
	}

	// HTTP verification
	m.Add(&autocert.Request{
		Hosts: []string{"example.dev", "www.example.dev"},
	})

	// DNS verification
	m.Add(&autocert.Request{
		Hosts:           []string{"dns.example.dev"},
		DNSProviderName: autocert.DNSimpleProvider,
		DNSCredentials:  []string{"API_KEY"},
	})

	go http.ListenAndServe(":8080", m.HTTPHandler(nil))
	// m.Run() // optional blocking call to ensure all certificates are issued before starting https server
	// go m.Monitor() // optionally renew certificates in the background
	s := &http.Server{
		Addr:      ":4443",
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	s.ListenAndServeTLS("", "")
}
